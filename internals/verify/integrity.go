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

	"github.com/karvashish/hardline/pkg/logger"
)

const (
	manifestFileName = "manifest.json"
	manifestSigName  = "manifest.sig"

	overridesFileName = "profile.overrides.json"

	LocalKeyPath = "/etc/hardline/profile_signing_pub.pem"

	maxProfileFileBytes  = 1 << 20
	maxProfileTotalBytes = 16 << 20
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

type VerifiedManifest struct {
	Digest string
	Files  map[string][]byte
}

func VerifyProfileIntegrity(profileDir string, useLocalKey bool) (*VerifiedManifest, error) {
	manifestPath := filepath.Join(profileDir, manifestFileName)
	manifestSigPath := filepath.Join(profileDir, manifestSigName)

	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read manifest %q: %w", manifestPath, err)
	}

	pubKey, err := resolvePublicKey(useLocalKey)
	if err != nil {
		return nil, err
	}

	if err := verifyManifestSignature(manifestBytes, manifestSigPath, pubKey); err != nil {
		return nil, err
	}

	var manifest profileManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("decode manifest %q: %w", manifestPath, err)
	}

	if manifest.Version != 1 {
		return nil, fmt.Errorf("manifest version %d is unsupported (expected 1)", manifest.Version)
	}
	if strings.ToLower(strings.TrimSpace(manifest.Algorithm)) != "sha256" {
		return nil, fmt.Errorf("manifest algorithm %q is unsupported (expected sha256)", manifest.Algorithm)
	}

	expected := make(map[string]string, len(manifest.Files))
	for _, entry := range manifest.Files {
		normalized, err := normalizeManifestPath(entry.Path)
		if err != nil {
			return nil, fmt.Errorf("invalid manifest path %q: %w", entry.Path, err)
		}

		sum := strings.ToLower(strings.TrimSpace(entry.SHA256))
		if len(sum) != 64 {
			return nil, fmt.Errorf("invalid sha256 length for %q: got %d, expected 64", normalized, len(sum))
		}
		if _, err := hex.DecodeString(sum); err != nil {
			return nil, fmt.Errorf("invalid sha256 hex for %q: %w", normalized, err)
		}
		if _, exists := expected[normalized]; exists {
			return nil, fmt.Errorf("duplicate manifest entry for %q", normalized)
		}
		expected[normalized] = sum
	}

	actual, err := collectProfileFiles(profileDir)
	if err != nil {
		return nil, err
	}

	for rel := range actual {
		if _, ok := expected[rel]; !ok {
			return nil, fmt.Errorf("unexpected file not listed in manifest: %s", rel)
		}
	}
	files := make(map[string][]byte, len(expected))
	for rel, want := range expected {
		content, ok := actual[rel]
		if !ok {
			return nil, fmt.Errorf("manifest references missing file: %s", rel)
		}
		if got := digestBytes(content); got != want {
			return nil, fmt.Errorf("hash mismatch for %s: expected %s got %s", rel, want, got)
		}
		files[rel] = content
	}

	return &VerifiedManifest{Digest: digestBytes(manifestBytes), Files: files}, nil
}

func digestBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func verifyManifestSignature(manifestBytes []byte, sigPath string, pubKey ed25519.PublicKey) error {
	sigText, err := os.ReadFile(sigPath)
	if err != nil {
		return fmt.Errorf("read manifest signature %q: %w", sigPath, err)
	}

	sigRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigText)))
	if err != nil {
		return fmt.Errorf("decode manifest signature %q as base64: %w", sigPath, err)
	}

	if !ed25519.Verify(pubKey, manifestBytes, sigRaw) {
		return fmt.Errorf("manifest signature verification failed")
	}

	return nil
}

func resolvePublicKey(useLocalKey bool) (ed25519.PublicKey, error) {
	if !useLocalKey {
		return parseEmbeddedPublicKey()
	}

	logger.Debugf("verify: using local signing key from %s\n", LocalKeyPath)
	return loadLocalPublicKey(LocalKeyPath)
}

func loadLocalPublicKey(keyPath string) (ed25519.PublicKey, error) {
	file, err := openNoFollow(keyPath)
	if err != nil {
		return nil, fmt.Errorf("local signing key not found at %s: %w", keyPath, err)
	}
	defer file.Close()

	// Every check below describes the descriptor that is about to be read, so there is no window
	// between what was checked and what is trusted, and no symlink to be redirected through.
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("read local signing key %s: %w", keyPath, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("local signing key %s is not a regular file (mode %s)", keyPath, info.Mode())
	}
	if mode := info.Mode().Perm(); mode&0o022 != 0 {
		return nil, fmt.Errorf(
			"local signing key %s has insecure permissions %04o: must not be group-writable or world-writable (expected 0644 or stricter)",
			keyPath, mode,
		)
	}
	if uid, ok := fileOwnerUID(info); ok && uid != 0 {
		return nil, fmt.Errorf(
			"local signing key %s is owned by uid %d: a trust anchor has to be root-owned, or that uid can replace the key hardline verifies against",
			keyPath, uid,
		)
	}

	pemBytes, err := io.ReadAll(io.LimitReader(file, maxProfileFileBytes))
	if err != nil {
		return nil, fmt.Errorf("read local signing key %s: %w", keyPath, err)
	}

	return parsePEMPublicKey(pemBytes, "local signing key "+keyPath)
}

func parseEmbeddedPublicKey() (ed25519.PublicKey, error) {
	return parsePEMPublicKey(embeddedProfileSigningPubPEM, "embedded profile signing public key")
}

func parsePEMPublicKey(pemData []byte, label string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("%s is not valid PEM", label)
	}

	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", label, err)
	}

	pub, ok := pubAny.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s is not Ed25519", label)
	}
	return pub, nil
}

func collectProfileFiles(profileDir string) (map[string][]byte, error) {
	files := make(map[string][]byte)
	total := 0

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

		if rel == manifestFileName || rel == manifestSigName || rel == overridesFileName {
			return nil
		}

		if !d.Type().IsRegular() {
			return fmt.Errorf("unsupported non-regular profile file: %s", rel)
		}

		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("stat profile file %s: %w", rel, err)
		}
		if info.Size() > maxProfileFileBytes {
			return fmt.Errorf("profile file %s is %d bytes, over the %d byte limit", rel, info.Size(), maxProfileFileBytes)
		}

		content, err := os.ReadFile(fullPath)
		if err != nil {
			return fmt.Errorf("read file %s: %w", rel, err)
		}
		if len(content) > maxProfileFileBytes {
			return fmt.Errorf("profile file %s is %d bytes, over the %d byte limit", rel, len(content), maxProfileFileBytes)
		}
		total += len(content)
		if total > maxProfileTotalBytes {
			return fmt.Errorf("profile directory exceeds the %d byte total limit", maxProfileTotalBytes)
		}

		files[rel] = content
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk profile directory %q: %w", profileDir, err)
	}

	return files, nil
}

func normalizeManifestPath(rel string) (string, error) {
	rel = path.Clean(filepath.ToSlash(strings.TrimSpace(rel)))
	if rel == "." || rel == "" {
		return "", fmt.Errorf("empty path")
	}
	if rel == manifestFileName || rel == manifestSigName {
		return "", fmt.Errorf("path must not reference manifest metadata files")
	}
	if rel == overridesFileName {
		return "", fmt.Errorf("path must not reference the runtime overrides file %q", overridesFileName)
	}
	if strings.HasPrefix(rel, "/") || strings.HasPrefix(rel, "../") || rel == ".." {
		return "", fmt.Errorf("path must be inside profile directory")
	}
	return rel, nil
}

func BuildProfileManifest(profileDir string) (*profileManifest, error) {
	files, err := collectProfileFiles(profileDir)
	if err != nil {
		return nil, err
	}

	paths := make([]string, 0, len(files))
	for rel := range files {
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
			SHA256: digestBytes(files[rel]),
		})
	}

	return manifest, nil
}
