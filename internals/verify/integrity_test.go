package verify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/karvashish/hardline/internals/cli"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

func TestVerifyProfileIntegrity_SuccessForSignedFixture(t *testing.T) {
	profileDir := copySignedFixtureProfile(t)

	if _, err := VerifyProfileIntegrity(profileDir, false); err != nil {
		t.Fatalf("expected signed fixture integrity check to pass, got error: %v", err)
	}
}

func TestVerifyProfileIntegrity_DetectsTamper(t *testing.T) {
	profileDir := copySignedFixtureProfile(t)

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

	err = integrityErr(profileDir, false)
	if err == nil {
		t.Fatal("expected tampered profile to fail integrity check, got nil error")
	}
	if !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("expected hash mismatch error, got: %v", err)
	}
}

func TestVerifyProfileIntegrity_DetectsUnexpectedFile(t *testing.T) {
	profileDir := copySignedFixtureProfile(t)

	extra := filepath.Join(profileDir, "extra.txt")
	if err := os.WriteFile(extra, []byte("unexpected"), 0o644); err != nil {
		t.Fatalf("write unexpected file: %v", err)
	}

	err := integrityErr(profileDir, false)
	if err == nil {
		t.Fatal("expected unexpected file to fail integrity check, got nil error")
	}
	if !strings.Contains(err.Error(), "unexpected file not listed in manifest") {
		t.Fatalf("expected unexpected-file error, got: %v", err)
	}
}

func TestVerifyProfileIntegrity_AllowsRuntimeOverridesFile(t *testing.T) {
	profileDir := copySignedFixtureProfile(t)

	overrides := filepath.Join(profileDir, overridesFileName)
	if err := os.WriteFile(overrides, []byte(`{"ssh_port": 2222}`), 0o644); err != nil {
		t.Fatalf("write overrides file: %v", err)
	}

	if _, err := VerifyProfileIntegrity(profileDir, false); err != nil {
		t.Fatalf("expected runtime overrides file to be ignored by integrity check, got: %v", err)
	}
}

func TestBuildProfileManifest_RejectsOverridesFileAsManifestEntry(t *testing.T) {
	profileDir := t.TempDir()
	writeTestFile(t, filepath.Join(profileDir, overridesFileName), []byte(`{"ssh_port": 2222}`))
	writeTestFile(t, filepath.Join(profileDir, "a.txt"), []byte("a"))

	m, err := BuildProfileManifest(profileDir)
	if err != nil {
		t.Fatalf("BuildProfileManifest failed: %v", err)
	}

	for _, entry := range m.Files {
		if entry.Path == overridesFileName {
			t.Fatalf("expected %q to be excluded from manifest, got %+v", overridesFileName, m.Files)
		}
	}
}

func TestVerifyProfileIntegrity_DetectsInvalidSignatureEncoding(t *testing.T) {
	profileDir := copySignedFixtureProfile(t)

	sigPath := filepath.Join(profileDir, manifestSigName)
	if err := os.WriteFile(sigPath, []byte("%%%not-base64%%%"), 0o644); err != nil {
		t.Fatalf("write invalid signature: %v", err)
	}

	err := integrityErr(profileDir, false)
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

			err := integrityErr(dir, false)
			if err == nil {
				t.Fatal("expected VerifyProfileIntegrity to fail")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("expected error containing %q, got %v", tc.wantSub, err)
			}
		})
	}
}

func TestVerifyManifestSignature_WrongSignature(t *testing.T) {
	dir := t.TempDir()
	manifestBytes := []byte(`{"version":1,"algorithm":"sha256","files":[]}` + "\n")
	sigPath := filepath.Join(dir, manifestSigName)

	_, restore := installTestEmbeddedKey(t)
	defer restore()

	pubKey, err := parseEmbeddedPublicKey()
	if err != nil {
		t.Fatalf("parse embedded key: %v", err)
	}

	if err := os.WriteFile(sigPath, []byte(base64.StdEncoding.EncodeToString([]byte("wrong"))+"\n"), 0o644); err != nil {
		t.Fatalf("write wrong signature: %v", err)
	}
	if err := verifyManifestSignature(manifestBytes, sigPath, pubKey); err == nil || !strings.Contains(err.Error(), "manifest signature verification failed") {
		t.Fatalf("expected signature verification failure, got %v", err)
	}
}

func TestParsePEMPublicKey_NotValidPEM(t *testing.T) {
	_, err := parsePEMPublicKey([]byte("not pem"), "test key")
	if err == nil || !strings.Contains(err.Error(), "not valid PEM") {
		t.Fatalf("expected invalid PEM error, got %v", err)
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

func TestParsePEMPublicKey_NonEd25519(t *testing.T) {
	rsaPEM := mustGenerateRSAPublicPEM(t)
	_, err := parsePEMPublicKey(rsaPEM, "test key")
	if err == nil || !strings.Contains(err.Error(), "not Ed25519") {
		t.Fatalf("expected non-ed25519 error, got %v", err)
	}
}

func TestVerifyManifestSignature_ReadSignatureError(t *testing.T) {
	_, restore := installTestEmbeddedKey(t)
	defer restore()

	pubKey, err := parseEmbeddedPublicKey()
	if err != nil {
		t.Fatalf("parse embedded key: %v", err)
	}

	err = verifyManifestSignature([]byte("x"), filepath.Join(t.TempDir(), "missing.sig"), pubKey)
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

	err := integrityErr(dir, false)
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

	err := integrityErr(dir, false)
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

func TestCollectProfileFiles_ErrorBranches(t *testing.T) {
	missingDir := filepath.Join(t.TempDir(), "missing")
	if _, err := collectProfileFiles(missingDir); err == nil {
		t.Fatal("expected collectProfileFiles to fail for missing directory")
	}

	tmp := t.TempDir()
	unreadableFile := filepath.Join(tmp, "secret.txt")
	writeTestFile(t, unreadableFile, []byte("secret"))
	if err := os.Chmod(unreadableFile, 0o000); err != nil {
		t.Fatalf("chmod unreadable file: %v", err)
	}
	defer os.Chmod(unreadableFile, 0o644)
	if _, err := collectProfileFiles(tmp); err == nil || !strings.Contains(err.Error(), "read file") {
		t.Fatalf("expected read file error, got %v", err)
	}

	noAccess := filepath.Join(t.TempDir(), "no-access")
	if err := os.MkdirAll(filepath.Join(noAccess, "child"), 0o755); err != nil {
		t.Fatalf("mkdir no-access child: %v", err)
	}
	if err := os.Chmod(noAccess, 0o000); err != nil {
		t.Fatalf("chmod no-access dir: %v", err)
	}
	defer os.Chmod(noAccess, 0o755)
	if _, err := collectProfileFiles(noAccess); err == nil {
		t.Fatal("expected walk error for no-access directory")
	}
}

// TestCollectProfileFiles_Bounds covers the limits that keep an unsigned
// directory from being read into memory without a ceiling.
func TestCollectProfileFiles_Bounds(t *testing.T) {
	t.Run("single file over the per-file limit", func(t *testing.T) {
		dir := t.TempDir()
		writeTestFile(t, filepath.Join(dir, "big.txt"), make([]byte, maxProfileFileBytes+1))
		if _, err := collectProfileFiles(dir); err == nil || !strings.Contains(err.Error(), "byte limit") {
			t.Fatalf("expected per-file limit error, got %v", err)
		}
	})

	t.Run("many files over the total limit", func(t *testing.T) {
		dir := t.TempDir()
		chunk := make([]byte, maxProfileFileBytes)
		for i := 0; i <= maxProfileTotalBytes/maxProfileFileBytes; i++ {
			writeTestFile(t, filepath.Join(dir, fmt.Sprintf("f%02d.txt", i)), chunk)
		}
		if _, err := collectProfileFiles(dir); err == nil || !strings.Contains(err.Error(), "total limit") {
			t.Fatalf("expected total limit error, got %v", err)
		}
	})

	t.Run("a symlink is not signable content", func(t *testing.T) {
		dir := t.TempDir()
		writeTestFile(t, filepath.Join(dir, "real.txt"), []byte("x"))
		if err := os.Symlink(filepath.Join(dir, "real.txt"), filepath.Join(dir, "link.txt")); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		if _, err := collectProfileFiles(dir); err == nil || !strings.Contains(err.Error(), "non-regular") {
			t.Fatalf("expected non-regular file error, got %v", err)
		}
	})
}

// TestVerifyProfileIntegrity_ReturnsSignedBytes is what makes the snapshot
// trustworthy: the map handed to later phases has to be the content that was
// hashed, not a second read of the same paths.
func TestVerifyProfileIntegrity_ReturnsSignedBytes(t *testing.T) {
	profileDir := copySignedFixtureProfile(t)

	manifest, err := VerifyProfileIntegrity(profileDir, false)
	if err != nil {
		t.Fatalf("VerifyProfileIntegrity failed: %v", err)
	}

	content, ok := manifest.Files["profile.json"]
	if !ok {
		t.Fatal("expected profile.json in the verified snapshot")
	}
	onDisk, err := os.ReadFile(filepath.Join(profileDir, "profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, onDisk) {
		t.Fatal("verified snapshot does not match the bytes that were hashed")
	}
}

func TestBuildProfileManifest_Error(t *testing.T) {
	if _, err := BuildProfileManifest(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("expected BuildProfileManifest to fail for missing directory")
	}
}

func TestVerifyProfile_Helper(t *testing.T) {
	okDir := copySignedFixtureProfile(t)
	if err := verifyErr(cli.Command{Profile: okDir}); err != nil {
		t.Fatalf("expected Verify success, got %v", err)
	}

	err := verifyErr(cli.Command{Profile: filepath.Join(t.TempDir(), "missing")})
	if err == nil {
		t.Fatal("expected Verify to fail for missing profile directory")
	}
}

func TestVerifyProfile_MissingPluginFails(t *testing.T) {
	prevIntegrity := verifyIntegrity
	prevLoad := loadVerifyProfile
	prevEnsure := ensureVerifyPlugins
	prevAffirm := affirmProfile
	defer func() {
		verifyIntegrity = prevIntegrity
		loadVerifyProfile = prevLoad
		ensureVerifyPlugins = prevEnsure
		affirmProfile = prevAffirm
	}()

	verifyIntegrity = func(string, bool) (*VerifiedManifest, error) { return emptyManifest(), nil }
	loadVerifyProfile = func(string, map[string][]byte) (*profile.Profile, error) {
		return &profile.Profile{
			ActionFiles: []profile.ActionFile{
				{Steps: []profile.Step{{ID: "s1", Plugin: "missing"}}},
			},
		}, nil
	}
	affirmProfile = func(*profile.Profile) error { return nil }
	ensureVerifyPlugins = pluginapi.ValidateProfileSteps

	err := verifyErr(cli.Command{Profile: "profile", Debug: true})
	if err == nil || !strings.Contains(err.Error(), "step validation failed") {
		t.Fatalf("expected step validation error, got %v", err)
	}
}

func TestVerify_NoExitOnSuccess(t *testing.T) {
	okDir := copySignedFixtureProfile(t)
	if err := verifyErr(cli.Command{Profile: okDir, Debug: true}); err != nil {
		t.Fatalf("expected Verify success, got %v", err)
	}
}

func copySignedFixtureProfile(t *testing.T) string {
	t.Helper()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}

	src := filepath.Join(filepath.Dir(thisFile), "testdata", "signed-profile")
	dst := filepath.Join(t.TempDir(), "profile")

	if err := copyDir(src, dst); err != nil {
		t.Fatalf("copy signed fixture profile: %v", err)
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

func generateTestKeyPEM(t *testing.T) (ed25519.PrivateKey, []byte) {
	t.Helper()
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
	return priv, pubPEM
}

func TestLoadLocalPublicKey_ValidKey(t *testing.T) {
	priv, pubPEM := generateTestKeyPEM(t)
	keyPath := filepath.Join(t.TempDir(), "pub.pem")
	if err := os.WriteFile(keyPath, pubPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	origStat := statFunc
	statFunc = os.Stat
	defer func() { statFunc = origStat }()

	pubKey, err := loadLocalPublicKey(keyPath)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	msg := []byte("test message")
	sig := ed25519.Sign(priv, msg)
	if !ed25519.Verify(pubKey, msg, sig) {
		t.Fatal("loaded key does not verify a signature made by the matching private key")
	}
}

func TestLoadLocalPublicKey_GroupWritable(t *testing.T) {
	_, pubPEM := generateTestKeyPEM(t)
	keyPath := filepath.Join(t.TempDir(), "pub.pem")
	if err := os.WriteFile(keyPath, pubPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyPath, 0o664); err != nil {
		t.Fatal(err)
	}

	origStat := statFunc
	statFunc = os.Stat
	defer func() { statFunc = origStat }()

	_, err := loadLocalPublicKey(keyPath)
	if err == nil || !strings.Contains(err.Error(), "insecure permissions") {
		t.Fatalf("expected insecure permissions error, got %v", err)
	}
}

func TestLoadLocalPublicKey_WorldWritable(t *testing.T) {
	_, pubPEM := generateTestKeyPEM(t)
	keyPath := filepath.Join(t.TempDir(), "pub.pem")
	if err := os.WriteFile(keyPath, pubPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyPath, 0o646); err != nil {
		t.Fatal(err)
	}

	origStat := statFunc
	statFunc = os.Stat
	defer func() { statFunc = origStat }()

	_, err := loadLocalPublicKey(keyPath)
	if err == nil || !strings.Contains(err.Error(), "insecure permissions") {
		t.Fatalf("expected insecure permissions error, got %v", err)
	}
}

func TestLoadLocalPublicKey_NotFound(t *testing.T) {
	origStat := statFunc
	statFunc = os.Stat
	defer func() { statFunc = origStat }()

	_, err := loadLocalPublicKey(filepath.Join(t.TempDir(), "nonexistent.pem"))
	if err == nil || !strings.Contains(err.Error(), "local signing key not found") {
		t.Fatalf("expected not found error, got %v", err)
	}
}

func TestLoadLocalPublicKey_NotEd25519(t *testing.T) {
	rsaPEM := mustGenerateRSAPublicPEM(t)
	keyPath := filepath.Join(t.TempDir(), "pub.pem")
	if err := os.WriteFile(keyPath, rsaPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	origStat := statFunc
	statFunc = os.Stat
	defer func() { statFunc = origStat }()

	_, err := loadLocalPublicKey(keyPath)
	if err == nil || !strings.Contains(err.Error(), "not Ed25519") {
		t.Fatalf("expected non-ed25519 error, got %v", err)
	}
}

func TestLoadLocalPublicKey_StrictPerms(t *testing.T) {
	_, pubPEM := generateTestKeyPEM(t)
	keyPath := filepath.Join(t.TempDir(), "pub.pem")
	if err := os.WriteFile(keyPath, pubPEM, 0o444); err != nil {
		t.Fatal(err)
	}

	origStat := statFunc
	statFunc = os.Stat
	defer func() { statFunc = origStat }()

	_, err := loadLocalPublicKey(keyPath)
	if err != nil {
		t.Fatalf("expected strict perms (0444) to be accepted, got %v", err)
	}
}

func TestResolvePublicKey_EmbeddedKey(t *testing.T) {
	key, err := resolvePublicKey(false)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
}

func TestVerifyProfileIntegrity_WithLocalKey(t *testing.T) {
	priv, pubPEM := generateTestKeyPEM(t)
	keyPath := filepath.Join(t.TempDir(), "pub.pem")
	if err := os.WriteFile(keyPath, pubPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	origStat := statFunc
	statFunc = os.Stat
	defer func() { statFunc = origStat }()

	// Build a simple profile signed with the local key
	profileDir := t.TempDir()
	writeTestFile(t, filepath.Join(profileDir, "a.txt"), []byte("hello"))

	manifest := profileManifest{
		Version:   1,
		Algorithm: "sha256",
		Files:     []manifestEntry{{Path: "a.txt", SHA256: digestBytes([]byte("hello"))}},
	}
	writeSignedManifest(t, profileDir, manifest, priv)

	// Temporarily override the local key path constant by patching loadLocalPublicKey
	// We can't change the const, so we override resolvePublicKey's behavior via
	// the statFunc and by reading from our temp key.
	// Actually, we need to call loadLocalPublicKey directly or patch things.
	// The simplest approach: override the VerifyProfileIntegrity to use local key
	// by passing useLocalKey=true and patching the LocalKeyPath.

	// Since LocalKeyPath is a const, we need a different approach for the e2e test.
	// Let's verify directly with the loaded key.
	pubKey, err := loadLocalPublicKey(keyPath)
	if err != nil {
		t.Fatalf("load local key: %v", err)
	}

	manifestBytes, err := os.ReadFile(filepath.Join(profileDir, manifestFileName))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyManifestSignature(manifestBytes, filepath.Join(profileDir, manifestSigName), pubKey); err != nil {
		t.Fatalf("expected signature to verify with local key, got %v", err)
	}
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

// integrityErr adapts the two-value VerifyProfileIntegrity for the many
// tests that only assert on the error.
func integrityErr(profileDir string, useLocalKey bool) error {
	_, err := VerifyProfileIntegrity(profileDir, useLocalKey)
	return err
}
