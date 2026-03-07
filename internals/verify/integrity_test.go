package verify

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/karvashish/hardline/internals/cli"
)

func TestVerifyProfileIntegrity_SuccessForBundledProfile(t *testing.T) {
	profileDir := copyBundledProfile(t)

	if err := VerifyProfileIntegrity(profileDir); err != nil {
		t.Fatalf("expected bundled profile integrity check to pass, got error: %v", err)
	}
}

func TestVerifyProfileIntegrity_DetectsTamper(t *testing.T) {
	profileDir := copyBundledProfile(t)

	target := filepath.Join(profileDir, "templates", "10-ssh-sshd-config.tmpl")
	f, err := os.OpenFile(target, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatalf("open tamper target: %v", err)
	}
	if _, err := f.WriteString("\n# tampered\n"); err != nil {
		f.Close()
		t.Fatalf("tamper write failed: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close tamper target: %v", err)
	}

	err = VerifyProfileIntegrity(profileDir)
	if err == nil {
		t.Fatal("expected tampered profile to fail integrity check, got nil error")
	}
	if !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("expected hash mismatch error, got: %v", err)
	}
}

func TestVerifyProfileIntegrity_DetectsUnexpectedFile(t *testing.T) {
	profileDir := copyBundledProfile(t)

	extra := filepath.Join(profileDir, "extra.txt")
	if err := os.WriteFile(extra, []byte("unexpected"), 0o644); err != nil {
		t.Fatalf("write unexpected file: %v", err)
	}

	err := VerifyProfileIntegrity(profileDir)
	if err == nil {
		t.Fatal("expected unexpected file to fail integrity check, got nil error")
	}
	if !strings.Contains(err.Error(), "unexpected file not listed in manifest") {
		t.Fatalf("expected unexpected-file error, got: %v", err)
	}
}

func TestVerifyProfileIntegrity_DetectsInvalidSignatureEncoding(t *testing.T) {
	profileDir := copyBundledProfile(t)

	sigPath := filepath.Join(profileDir, manifestSigName)
	if err := os.WriteFile(sigPath, []byte("%%%not-base64%%%"), 0o644); err != nil {
		t.Fatalf("write invalid signature: %v", err)
	}

	err := VerifyProfileIntegrity(profileDir)
	if err == nil {
		t.Fatal("expected invalid signature to fail integrity check, got nil error")
	}
	if !strings.Contains(err.Error(), "decode manifest signature") {
		t.Fatalf("expected signature decode error, got: %v", err)
	}
}

func TestBuildProfileManifest_ExcludesManifestFilesAndSorts(t *testing.T) {
	profileDir := t.TempDir()
	writeTestFile(t, filepath.Join(profileDir, "b.txt"), []byte("b"))
	writeTestFile(t, filepath.Join(profileDir, "a.txt"), []byte("a"))
	writeTestFile(t, filepath.Join(profileDir, manifestFileName), []byte("{}"))
	writeTestFile(t, filepath.Join(profileDir, manifestSigName), []byte(base64.StdEncoding.EncodeToString([]byte("x"))))

	m, err := BuildProfileManifest(profileDir)
	if err != nil {
		t.Fatalf("BuildProfileManifest failed: %v", err)
	}

	if m.Version != 1 {
		t.Fatalf("expected manifest version 1, got %d", m.Version)
	}
	if m.Algorithm != "sha256" {
		t.Fatalf("expected algorithm sha256, got %q", m.Algorithm)
	}

	if len(m.Files) != 2 {
		out, _ := json.Marshal(m.Files)
		t.Fatalf("expected 2 manifest entries, got %d: %s", len(m.Files), string(out))
	}
	if m.Files[0].Path != "a.txt" || m.Files[1].Path != "b.txt" {
		t.Fatalf("expected sorted file list [a.txt b.txt], got [%s %s]", m.Files[0].Path, m.Files[1].Path)
	}
}

func TestVerifyProfileIntegrity_ManifestValidationBranches(t *testing.T) {
	cases := []struct {
		name      string
		manifest  profileManifest
		wantSub   string
		setupFile func(dir string)
	}{
		{
			name: "unsupported version",
			manifest: profileManifest{
				Version:   2,
				Algorithm: "sha256",
				Files: []manifestEntry{
					{Path: "a.txt", SHA256: strings.Repeat("0", 64)},
				},
			},
			wantSub: "manifest version",
			setupFile: func(dir string) {
				writeTestFile(t, filepath.Join(dir, "a.txt"), []byte("a"))
			},
		},
		{
			name: "unsupported algorithm",
			manifest: profileManifest{
				Version:   1,
				Algorithm: "sha1",
				Files: []manifestEntry{
					{Path: "a.txt", SHA256: strings.Repeat("0", 64)},
				},
			},
			wantSub: "manifest algorithm",
			setupFile: func(dir string) {
				writeTestFile(t, filepath.Join(dir, "a.txt"), []byte("a"))
			},
		},
		{
			name: "duplicate entries",
			manifest: profileManifest{
				Version:   1,
				Algorithm: "sha256",
				Files: []manifestEntry{
					{Path: "a.txt", SHA256: strings.Repeat("0", 64)},
					{Path: "a.txt", SHA256: strings.Repeat("1", 64)},
				},
			},
			wantSub: "duplicate manifest entry",
			setupFile: func(dir string) {
				writeTestFile(t, filepath.Join(dir, "a.txt"), []byte("a"))
			},
		},
		{
			name: "invalid path traversal",
			manifest: profileManifest{
				Version:   1,
				Algorithm: "sha256",
				Files: []manifestEntry{
					{Path: "../a.txt", SHA256: strings.Repeat("0", 64)},
				},
			},
			wantSub: "invalid manifest path",
			setupFile: func(dir string) {
				writeTestFile(t, filepath.Join(dir, "a.txt"), []byte("a"))
			},
		},
		{
			name: "invalid sha length",
			manifest: profileManifest{
				Version:   1,
				Algorithm: "sha256",
				Files: []manifestEntry{
					{Path: "a.txt", SHA256: "abcd"},
				},
			},
			wantSub: "invalid sha256 length",
			setupFile: func(dir string) {
				writeTestFile(t, filepath.Join(dir, "a.txt"), []byte("a"))
			},
		},
		{
			name: "invalid sha hex",
			manifest: profileManifest{
				Version:   1,
				Algorithm: "sha256",
				Files: []manifestEntry{
					{Path: "a.txt", SHA256: strings.Repeat("z", 64)},
				},
			},
			wantSub: "invalid sha256 hex",
			setupFile: func(dir string) {
				writeTestFile(t, filepath.Join(dir, "a.txt"), []byte("a"))
			},
		},
		{
			name: "manifest missing file",
			manifest: profileManifest{
				Version:   1,
				Algorithm: "sha256",
				Files: []manifestEntry{
					{Path: "missing.txt", SHA256: strings.Repeat("0", 64)},
				},
			},
			wantSub:   "manifest references missing file",
			setupFile: func(string) {},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tc.setupFile(dir)

			priv, restore := installTestEmbeddedKey(t)
			defer restore()

			writeSignedManifest(t, dir, tc.manifest, priv)

			err := VerifyProfileIntegrity(dir)
			if err == nil {
				t.Fatal("expected VerifyProfileIntegrity to fail")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("expected error containing %q, got %v", tc.wantSub, err)
			}
		})
	}
}

func TestVerifyManifestSignature_AndPublicKeyParseFailures(t *testing.T) {
	dir := t.TempDir()
	manifestBytes := []byte(`{"version":1,"algorithm":"sha256","files":[]}` + "\n")
	manifestPath := filepath.Join(dir, manifestFileName)
	sigPath := filepath.Join(dir, manifestSigName)
	writeTestFile(t, manifestPath, manifestBytes)

	_, restore := installTestEmbeddedKey(t)
	defer restore()

	// valid base64 but incorrect signature bytes
	if err := os.WriteFile(sigPath, []byte(base64.StdEncoding.EncodeToString([]byte("wrong"))+"\n"), 0o644); err != nil {
		t.Fatalf("write wrong signature: %v", err)
	}
	if err := verifyManifestSignature(manifestBytes, sigPath); err == nil || !strings.Contains(err.Error(), "manifest signature verification failed") {
		t.Fatalf("expected signature verification failure, got %v", err)
	}

	// now make parsing fail: invalid PEM in embedded key
	embeddedProfileSigningPubPEM = []byte("not pem")
	if err := verifyManifestSignature(manifestBytes, sigPath); err == nil || !strings.Contains(err.Error(), "not valid PEM") {
		t.Fatalf("expected invalid embedded key PEM error, got %v", err)
	}
}

func TestParseEmbeddedPublicKey_NonEd25519(t *testing.T) {
	_, restore := installTestEmbeddedKey(t)
	defer restore()

	embeddedProfileSigningPubPEM = mustGenerateRSAPublicPEM(t)
	if _, err := parseEmbeddedPublicKey(); err == nil || !strings.Contains(err.Error(), "not Ed25519") {
		t.Fatalf("expected non-ed25519 error, got %v", err)
	}
}

func TestParseEmbeddedPublicKey_ParseFailure(t *testing.T) {
	_, restore := installTestEmbeddedKey(t)
	defer restore()

	embeddedProfileSigningPubPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: []byte("bad-der"),
	})
	if _, err := parseEmbeddedPublicKey(); err == nil || !strings.Contains(err.Error(), "parse embedded profile signing public key") {
		t.Fatalf("expected embedded key parse error, got %v", err)
	}
}

func TestVerifyManifestSignature_ReadSignatureError(t *testing.T) {
	_, restore := installTestEmbeddedKey(t)
	defer restore()

	err := verifyManifestSignature([]byte("x"), filepath.Join(t.TempDir(), "missing.sig"))
	if err == nil || !strings.Contains(err.Error(), "read manifest signature") {
		t.Fatalf("expected read signature error, got %v", err)
	}
}

func TestVerifyProfileIntegrity_DecodeManifestError(t *testing.T) {
	dir := t.TempDir()
	priv, restore := installTestEmbeddedKey(t)
	defer restore()

	manifestBytes := []byte("{not-json}\n")
	writeTestFile(t, filepath.Join(dir, manifestFileName), manifestBytes)
	sig := ed25519.Sign(priv, manifestBytes)
	writeTestFile(t, filepath.Join(dir, manifestSigName), []byte(base64.StdEncoding.EncodeToString(sig)+"\n"))

	err := VerifyProfileIntegrity(dir)
	if err == nil || !strings.Contains(err.Error(), "decode manifest") {
		t.Fatalf("expected decode manifest error, got %v", err)
	}
}

func TestVerifyProfileIntegrity_CollectProfileHashesError(t *testing.T) {
	dir := t.TempDir()
	priv, restore := installTestEmbeddedKey(t)
	defer restore()

	target := filepath.Join(dir, "target.txt")
	writeTestFile(t, target, []byte("x"))
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	writeSignedManifest(t, dir, profileManifest{
		Version:   1,
		Algorithm: "sha256",
		Files:     []manifestEntry{},
	}, priv)

	err := VerifyProfileIntegrity(dir)
	if err == nil || !strings.Contains(err.Error(), "walk profile directory") {
		t.Fatalf("expected collectProfileHashes walk error, got %v", err)
	}
}

func TestNormalizeManifestPath_InvalidCases(t *testing.T) {
	cases := []string{"", ".", "..", "/abs", "../x", manifestFileName, manifestSigName}
	for _, in := range cases {
		if _, err := normalizeManifestPath(in); err == nil {
			t.Fatalf("expected normalizeManifestPath(%q) to fail", in)
		}
	}
	if out, err := normalizeManifestPath("a/b.txt"); err != nil || out != "a/b.txt" {
		t.Fatalf("expected normalizeManifestPath success, got out=%q err=%v", out, err)
	}
}

func TestCollectProfileHashes_ErrorBranches(t *testing.T) {
	missingDir := filepath.Join(t.TempDir(), "missing")
	if _, err := collectProfileHashes(missingDir); err == nil {
		t.Fatal("expected collectProfileHashes to fail for missing directory")
	}

	tmp := t.TempDir()
	unreadableFile := filepath.Join(tmp, "secret.txt")
	writeTestFile(t, unreadableFile, []byte("secret"))
	if err := os.Chmod(unreadableFile, 0o000); err != nil {
		t.Fatalf("chmod unreadable file: %v", err)
	}
	defer os.Chmod(unreadableFile, 0o644)
	if _, err := collectProfileHashes(tmp); err == nil || !strings.Contains(err.Error(), "hash file") {
		t.Fatalf("expected hash file error, got %v", err)
	}

	noAccess := filepath.Join(t.TempDir(), "no-access")
	if err := os.MkdirAll(filepath.Join(noAccess, "child"), 0o755); err != nil {
		t.Fatalf("mkdir no-access child: %v", err)
	}
	if err := os.Chmod(noAccess, 0o000); err != nil {
		t.Fatalf("chmod no-access dir: %v", err)
	}
	defer os.Chmod(noAccess, 0o755)
	if _, err := collectProfileHashes(noAccess); err == nil {
		t.Fatal("expected walk error for no-access directory")
	}
}

func TestSha256File_ErrorBranches(t *testing.T) {
	if _, err := sha256File(filepath.Join(t.TempDir(), "missing.txt")); err == nil {
		t.Fatal("expected open error for missing file")
	}

	dir := t.TempDir()
	if _, err := sha256File(dir); err == nil {
		t.Fatal("expected read/copy error when hashing directory")
	}
}

func TestBuildProfileManifest_Error(t *testing.T) {
	if _, err := BuildProfileManifest(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("expected BuildProfileManifest to fail for missing directory")
	}
}

func TestVerifyProfile_Helper(t *testing.T) {
	okDir := copyBundledProfile(t)
	if err := verifyProfile(cli.Command{Profile: okDir}); err != nil {
		t.Fatalf("expected verifyProfile success, got %v", err)
	}

	err := verifyProfile(cli.Command{Profile: filepath.Join(t.TempDir(), "missing")})
	if err == nil {
		t.Fatal("expected verifyProfile to fail for missing profile directory")
	}
}

func TestVerify_NoExitOnSuccess(t *testing.T) {
	okDir := copyBundledProfile(t)
	Verify(cli.Command{Profile: okDir, Debug: true})
}

func copyBundledProfile(t *testing.T) string {
	t.Helper()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}

	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	src := filepath.Join(repoRoot, "base-secure-ubuntu-24.04-lts")
	dst := filepath.Join(t.TempDir(), "profile")

	if err := copyDir(src, dst); err != nil {
		t.Fatalf("copy bundled profile: %v", err)
	}
	return dst
}

func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)

		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
}

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", path, err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func installTestEmbeddedKey(t *testing.T) (ed25519.PrivateKey, func()) {
	t.Helper()

	orig := make([]byte, len(embeddedProfileSigningPubPEM))
	copy(orig, embeddedProfileSigningPubPEM)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal ed25519 pub key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	})
	embeddedProfileSigningPubPEM = pubPEM

	restore := func() {
		embeddedProfileSigningPubPEM = orig
	}
	return priv, restore
}

func writeSignedManifest(t *testing.T, profileDir string, m profileManifest, priv ed25519.PrivateKey) {
	t.Helper()

	manifestBytes, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	manifestBytes = append(manifestBytes, '\n')

	writeTestFile(t, filepath.Join(profileDir, manifestFileName), manifestBytes)

	sig := ed25519.Sign(priv, manifestBytes)
	sigText := base64.StdEncoding.EncodeToString(sig) + "\n"
	writeTestFile(t, filepath.Join(profileDir, manifestSigName), []byte(sigText))
}

func mustGenerateRSAPublicPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal RSA pubkey: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	})
}
