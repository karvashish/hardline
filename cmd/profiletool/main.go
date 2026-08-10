package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"

	"github.com/karvashish/hardline/pkg/logger"
)

const embeddedVerifyPubKeyPath = "internals/verify/profile_signing_pub.pem"
const (
	manifestFileName  = "manifest.json"
	manifestSigName   = "manifest.sig"
	overridesFileName = "profile.overrides.json"
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

var (
	profileInfof  = logger.Infof
	profileErrorf = logger.Errorf
)

func usage() {
	profileErrorf(`Usage:
  go run ./cmd/profiletool <command> [options]

Commands:
  keygen   Generate Ed25519 key pair (PEM files)
  sign     Generate manifest.json and manifest.sig for a profile

Examples:
  go run ./cmd/profiletool keygen --private-out /tmp/profile_signing.key --public-out /tmp/profile_signing_pub.pem
  go run ./cmd/profiletool sign --profile-dir profiles/starter-secure-ubuntu-24.04-lts --private-key /tmp/profile_signing.key
`)
}

func main() {
	os.Exit(run(os.Args))
}

func run(args []string) int {
	if len(args) < 2 {
		usage()
		return 2
	}

	switch args[1] {
	case "keygen":
		if err := runKeygen(args[2:]); err != nil {
			profileErrorf("keygen failed: %v\n", err)
			return 1
		}
	case "sign":
		if err := runSign(args[2:]); err != nil {
			profileErrorf("sign failed: %v\n", err)
			return 1
		}
	default:
		usage()
		return 2
	}
	return 0
}

func runKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	privateOut := fs.String("private-out", "profile_signing.key", "output path for private key (PEM PKCS8)")
	publicOut := fs.String("public-out", "profile_signing_pub.pem", "output path for public key (PEM PKIX)")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %v", fs.Args())
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate ed25519 key pair: %w", err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal private key (PKCS8): %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("marshal public key (PKIX): %w", err)
	}

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privDER,
	})
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	})

	if err := writeFileWithPerm(*privateOut, privPEM, 0o600); err != nil {
		return fmt.Errorf("write private key %q: %w", *privateOut, err)
	}
	if err := writeFileWithPerm(*publicOut, pubPEM, 0o644); err != nil {
		return fmt.Errorf("write public key %q: %w", *publicOut, err)
	}
	if *publicOut != embeddedVerifyPubKeyPath {
		if err := writeFileWithPerm(embeddedVerifyPubKeyPath, pubPEM, 0o644); err != nil {
			return fmt.Errorf("write embedded verifier public key %q: %w", embeddedVerifyPubKeyPath, err)
		}
	}

	profileInfof("wrote private key: %s\n", *privateOut)
	profileInfof("wrote public key : %s\n", *publicOut)
	profileInfof("wrote embedded key: %s\n", embeddedVerifyPubKeyPath)
	profileInfof("rebuild hardline after key rotation so the new embedded public key is used\n")
	return nil
}

func runSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	profileDir := fs.String("profile-dir", "", "profile directory to sign")
	privateKeyPath := fs.String("private-key", "", "path to Ed25519 private key (PEM PKCS8)")
	manifestOut := fs.String("manifest-out", "", "output manifest path (default: <profile-dir>/manifest.json)")
	sigOut := fs.String("sig-out", "", "output signature path (default: <profile-dir>/manifest.sig)")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %v", fs.Args())
	}
	if *profileDir == "" {
		return fmt.Errorf("--profile-dir is required")
	}
	if *privateKeyPath == "" {
		return fmt.Errorf("--private-key is required")
	}

	manifestPath := *manifestOut
	if manifestPath == "" {
		manifestPath = filepath.Join(*profileDir, "manifest.json")
	}
	signaturePath := *sigOut
	if signaturePath == "" {
		signaturePath = filepath.Join(*profileDir, "manifest.sig")
	}

	privKey, err := loadEd25519PrivateKey(*privateKeyPath)
	if err != nil {
		return err
	}

	manifest, err := buildProfileManifest(*profileDir)
	if err != nil {
		return fmt.Errorf("build profile manifest: %w", err)
	}

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("encode manifest: %w", err)
	}
	manifestBytes = append(manifestBytes, '\n')

	if err := writeFileWithPerm(manifestPath, manifestBytes, 0o644); err != nil {
		return fmt.Errorf("write manifest %q: %w", manifestPath, err)
	}

	sig := ed25519.Sign(privKey, manifestBytes)
	sigB64 := []byte(base64.StdEncoding.EncodeToString(sig) + "\n")
	if err := writeFileWithPerm(signaturePath, sigB64, 0o644); err != nil {
		return fmt.Errorf("write signature %q: %w", signaturePath, err)
	}

	profileInfof("wrote manifest : %s\n", manifestPath)
	profileInfof("wrote signature: %s\n", signaturePath)
	return nil
}

func loadEd25519PrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key %q: %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("private key %q is not valid PEM", path)
	}

	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key %q as PKCS8: %w", path, err)
	}

	key, ok := keyAny.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key %q is not Ed25519", path)
	}
	return key, nil
}

func writeFileWithPerm(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	if err := os.WriteFile(path, data, perm); err != nil {
		return err
	}
	return os.Chmod(path, perm)
}

func buildProfileManifest(profileDir string) (*profileManifest, error) {
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

		if rel == manifestFileName || rel == manifestSigName || rel == overridesFileName {
			return nil
		}

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
