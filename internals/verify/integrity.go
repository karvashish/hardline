package verify

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

const (
	manifestFileName = "manifest.json"
	manifestSigName  = "manifest.sig"
)

type profileManifest struct {
	Version   int             `json:"version"`
	Algorithm string          `json:"algorithm"`
	Files     []manifestEntry `json:"files"`
}

type manifestEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

//go:embed profile_signing_pub.pem
var embeddedProfileSigningPubPEM []byte

func VerifyProfileIntegrity(profileDir string) error {
	manifestPath := filepath.Join(profileDir, manifestFileName)
	manifestSigPath := filepath.Join(profileDir, manifestSigName)

	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read manifest %q: %w", manifestPath, err)
	}

	if err := verifyManifestSignature(manifestBytes, manifestSigPath); err != nil {
		return err
	}

	var manifest profileManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return fmt.Errorf("decode manifest %q: %w", manifestPath, err)
	}

	if manifest.Version != 1 {
		return fmt.Errorf("manifest version %d is unsupported (expected 1)", manifest.Version)
	}
	if strings.ToLower(strings.TrimSpace(manifest.Algorithm)) != "sha256" {
		return fmt.Errorf("manifest algorithm %q is unsupported (expected sha256)", manifest.Algorithm)
	}

	expected := make(map[string]string, len(manifest.Files))
	for _, entry := range manifest.Files {
		normalized, err := normalizeManifestPath(entry.Path)
		if err != nil {
			return fmt.Errorf("invalid manifest path %q: %w", entry.Path, err)
		}

		sum := strings.ToLower(strings.TrimSpace(entry.SHA256))
		if len(sum) != 64 {
			return fmt.Errorf("invalid sha256 length for %q: got %d, expected 64", normalized, len(sum))
		}
		if _, err := hex.DecodeString(sum); err != nil {
			return fmt.Errorf("invalid sha256 hex for %q: %w", normalized, err)
		}
		if _, exists := expected[normalized]; exists {
			return fmt.Errorf("duplicate manifest entry for %q", normalized)
		}
		expected[normalized] = sum
	}

	actual, err := collectProfileHashes(profileDir)
	if err != nil {
		return err
	}

	for rel := range actual {
		if _, ok := expected[rel]; !ok {
			return fmt.Errorf("unexpected file not listed in manifest: %s", rel)
		}
	}
	for rel, want := range expected {
		got, ok := actual[rel]
		if !ok {
			return fmt.Errorf("manifest references missing file: %s", rel)
		}
		if got != want {
			return fmt.Errorf("hash mismatch for %s: expected %s got %s", rel, want, got)
		}
	}

	return nil
}

func verifyManifestSignature(manifestBytes []byte, sigPath string) error {
	sigText, err := os.ReadFile(sigPath)
	if err != nil {
		return fmt.Errorf("read manifest signature %q: %w", sigPath, err)
	}

	sigRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigText)))
	if err != nil {
		return fmt.Errorf("decode manifest signature %q as base64: %w", sigPath, err)
	}

	pubKey, err := parseEmbeddedPublicKey()
	if err != nil {
		return err
	}

	if !ed25519.Verify(pubKey, manifestBytes, sigRaw) {
		return fmt.Errorf("manifest signature verification failed")
	}

	return nil
}

func parseEmbeddedPublicKey() (ed25519.PublicKey, error) {
	block, _ := pem.Decode(embeddedProfileSigningPubPEM)
	if block == nil {
		return nil, fmt.Errorf("embedded profile signing public key is not valid PEM")
	}

	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse embedded profile signing public key: %w", err)
	}

	pub, ok := pubAny.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("embedded profile signing public key is not Ed25519")
	}
	return pub, nil
}

func collectProfileHashes(profileDir string) (map[string]string, error) {
	hashes := make(map[string]string)

	err := filepath.WalkDir(profileDir, func(fullPath string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(profileDir, fullPath)
		if err != nil {
			return fmt.Errorf("resolve relative path for %q: %w", fullPath, err)
		}
		rel = path.Clean(filepath.ToSlash(rel))

		if rel == manifestFileName || rel == manifestSigName {
			return nil
		}

		// Enforce strict byte-level integrity only for regular files.
		if !d.Type().IsRegular() {
			return fmt.Errorf("unsupported non-regular profile file: %s", rel)
		}

		sum, err := sha256File(fullPath)
		if err != nil {
			return fmt.Errorf("hash file %s: %w", rel, err)
		}
		hashes[rel] = sum
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk profile directory %q: %w", profileDir, err)
	}

	return hashes, nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

func normalizeManifestPath(rel string) (string, error) {
	rel = path.Clean(filepath.ToSlash(strings.TrimSpace(rel)))
	if rel == "." || rel == "" {
		return "", fmt.Errorf("empty path")
	}
	if rel == manifestFileName || rel == manifestSigName {
		return "", fmt.Errorf("path must not reference manifest metadata files")
	}
	if strings.HasPrefix(rel, "/") || strings.HasPrefix(rel, "../") || rel == ".." {
		return "", fmt.Errorf("path must be inside profile directory")
	}
	return rel, nil
}

func BuildProfileManifest(profileDir string) (*profileManifest, error) {
	hashes, err := collectProfileHashes(profileDir)
	if err != nil {
		return nil, err
	}

	paths := make([]string, 0, len(hashes))
	for rel := range hashes {
		paths = append(paths, rel)
	}
	sort.Strings(paths)

	manifest := &profileManifest{
		Version:   1,
		Algorithm: "sha256",
		Files:     make([]manifestEntry, 0, len(paths)),
	}

	for _, rel := range paths {
		manifest.Files = append(manifest.Files, manifestEntry{
			Path:   rel,
			SHA256: hashes[rel],
		})
	}

	return manifest, nil
}
