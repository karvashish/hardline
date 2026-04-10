package main

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
	"strings"
	"testing"
)

func TestRunKeygen_WritesExpectedKeyFiles(t *testing.T) {
	tmp := t.TempDir()

	withChdir(t, tmp, func() {
		err := runKeygen([]string{
			"--private-out", "keys/private.pem",
			"--public-out", "keys/public.pem",
		})
		if err != nil {
			t.Fatalf("runKeygen failed: %v", err)
		}

		privatePath := filepath.Join(tmp, "keys/private.pem")
		publicPath := filepath.Join(tmp, "keys/public.pem")
		embeddedPath := filepath.Join(tmp, embeddedVerifyPubKeyPath)

		assertFileExists(t, privatePath)
		assertFileExists(t, publicPath)
		assertFileExists(t, embeddedPath)

		privateMode := mustStat(t, privatePath).Mode().Perm()
		if privateMode != 0o600 {
			t.Fatalf("expected private key mode 0600, got %#o", privateMode)
		}

		publicMode := mustStat(t, publicPath).Mode().Perm()
		if publicMode != 0o644 {
			t.Fatalf("expected public key mode 0644, got %#o", publicMode)
		}

		pubKey := parseEd25519PublicKeyFromPEM(t, publicPath)
		privKey := parseEd25519PrivateKeyFromPEM(t, privatePath)
		if !privKey.Public().(ed25519.PublicKey).Equal(pubKey) {
			t.Fatal("generated private key does not match generated public key")
		}

		embeddedPub := parseEd25519PublicKeyFromPEM(t, embeddedPath)
		if !embeddedPub.Equal(pubKey) {
			t.Fatal("embedded verifier key does not match generated public key")
		}
	})
}

func TestRunSign_GeneratesManifestAndValidSignature(t *testing.T) {
	tmp := t.TempDir()
	profileDir := filepath.Join(tmp, "profile")

	writeTestFile(t, filepath.Join(profileDir, "profile.json"), []byte(`{"id":"x"}`))
	writeTestFile(t, filepath.Join(profileDir, "actions", "a.json"), []byte(`{"steps":[]}`))
	writeTestFile(t, filepath.Join(profileDir, "templates", "t.tmpl"), []byte("abc"))

	withChdir(t, tmp, func() {
		if err := runKeygen([]string{
			"--private-out", "keys/private.pem",
			"--public-out", "keys/public.pem",
		}); err != nil {
			t.Fatalf("runKeygen failed: %v", err)
		}

		if err := runSign([]string{
			"--profile-dir", profileDir,
			"--private-key", filepath.Join(tmp, "keys/private.pem"),
		}); err != nil {
			t.Fatalf("runSign failed: %v", err)
		}
	})

	manifestPath := filepath.Join(profileDir, manifestFileName)
	sigPath := filepath.Join(profileDir, manifestSigName)
	assertFileExists(t, manifestPath)
	assertFileExists(t, sigPath)

	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var m profileManifest
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if m.Version != 1 || m.Algorithm != "sha256" {
		t.Fatalf("unexpected manifest metadata: version=%d algorithm=%q", m.Version, m.Algorithm)
	}

	paths := map[string]bool{}
	for _, e := range m.Files {
		paths[e.Path] = true
	}
	if !paths["profile.json"] || !paths["actions/a.json"] || !paths["templates/t.tmpl"] {
		t.Fatalf("manifest missing expected files: %#v", paths)
	}
	if paths[manifestFileName] || paths[manifestSigName] {
		t.Fatalf("manifest should not include signature metadata files: %#v", paths)
	}

	sigText, err := os.ReadFile(sigPath)
	if err != nil {
		t.Fatalf("read signature: %v", err)
	}
	sigRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigText)))
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}

	pub := parseEd25519PublicKeyFromPEM(t, filepath.Join(tmp, "keys/public.pem"))
	if !ed25519.Verify(pub, manifestBytes, sigRaw) {
		t.Fatal("signature did not verify against generated public key")
	}
}

func TestRunSign_RequiresPrivateKey(t *testing.T) {
	err := runSign([]string{"--profile-dir", t.TempDir()})
	if err == nil {
		t.Fatal("expected runSign to fail when --private-key is missing")
	}
	if !strings.Contains(err.Error(), "--private-key is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRun_NoArgsAndUnknownCommand(t *testing.T) {
	restore := stubProfileToolLoggers()
	defer restore()

	var errOut bytes.Buffer
	profileErrorf = func(format string, args ...any) {
		_, _ = fmt.Fprintf(&errOut, format, args...)
	}
	if code := run([]string{"profiletool"}); code != 2 {
		t.Fatalf("expected exit code 2 for no args, got %d", code)
	}
	if !strings.Contains(errOut.String(), "Usage:") {
		t.Fatalf("expected usage output for no args, got %q", errOut.String())
	}

	errOut.Reset()
	if code := run([]string{"profiletool", "unknown"}); code != 2 {
		t.Fatalf("expected exit code 2 for unknown command, got %d", code)
	}
	if !strings.Contains(errOut.String(), "Usage:") {
		t.Fatalf("expected usage output for unknown command, got %q", errOut.String())
	}
}

func TestRun_CommandFailureCodes(t *testing.T) {
	restore := stubProfileToolLoggers()
	defer restore()

	var errOut bytes.Buffer
	profileErrorf = func(format string, args ...any) {
		_, _ = fmt.Fprintf(&errOut, format, args...)
	}
	if code := run([]string{"profiletool", "keygen", "--bad-flag"}); code != 1 {
		t.Fatalf("expected exit code 1 for keygen parse failure, got %d", code)
	}
	if !strings.Contains(errOut.String(), "keygen failed") {
		t.Fatalf("expected keygen failure prefix, got %q", errOut.String())
	}

	errOut.Reset()
	if code := run([]string{"profiletool", "sign", "--profile-dir", "x"}); code != 1 {
		t.Fatalf("expected exit code 1 for sign arg failure, got %d", code)
	}
	if !strings.Contains(errOut.String(), "sign failed") {
		t.Fatalf("expected sign failure prefix, got %q", errOut.String())
	}
}

func TestRun_SuccessPaths(t *testing.T) {
	restore := stubProfileToolLoggers()
	defer restore()

	tmp := t.TempDir()
	profileDir := filepath.Join(tmp, "profile")
	writeTestFile(t, filepath.Join(profileDir, "profile.json"), []byte(`{"name":"ok"}`))

	withChdir(t, tmp, func() {
		var errOut bytes.Buffer
		profileErrorf = func(format string, args ...any) {
			_, _ = fmt.Fprintf(&errOut, format, args...)
		}
		if code := run([]string{
			"profiletool", "keygen",
			"--private-out", "keys/private.pem",
			"--public-out", embeddedVerifyPubKeyPath,
		}); code != 0 {
			t.Fatalf("expected keygen success exit code 0, got %d, stderr=%q", code, errOut.String())
		}

		errOut.Reset()
		if code := run([]string{
			"profiletool", "sign",
			"--profile-dir", profileDir,
			"--private-key", filepath.Join(tmp, "keys/private.pem"),
		}); code != 0 {
			t.Fatalf("expected sign success exit code 0, got %d, stderr=%q", code, errOut.String())
		}
	})
}

func stubProfileToolLoggers() func() {
	prevInfo := profileInfof
	prevErr := profileErrorf
	return func() {
		profileInfof = prevInfo
		profileErrorf = prevErr
	}
}

func TestRunKeygen_Errors(t *testing.T) {
	withChdir(t, t.TempDir(), func() {
		if err := runKeygen([]string{"--private-out", "a.pem", "extra"}); err == nil {
			t.Fatal("expected positional-args error from runKeygen")
		}

		if err := runKeygen([]string{"--private-out", "/dev/null/key", "--public-out", "pub.pem"}); err == nil {
			t.Fatal("expected write failure for private key path under /dev/null")
		}
	})
}

func TestRunKeygen_PublicAndEmbeddedWriteFailures(t *testing.T) {
	withChdir(t, t.TempDir(), func() {
		err := runKeygen([]string{
			"--private-out", "keys/private.pem",
			"--public-out", "/dev/null/public.pem",
		})
		if err == nil || !strings.Contains(err.Error(), "write public key") {
			t.Fatalf("expected public key write failure, got %v", err)
		}
	})

	tmp := t.TempDir()
	withChdir(t, tmp, func() {
		writeTestFile(t, filepath.Join(tmp, "internals"), []byte("not a directory"))
		err := runKeygen([]string{
			"--private-out", "keys/private.pem",
			"--public-out", "keys/public.pem",
		})
		if err == nil || !strings.Contains(err.Error(), "write embedded verifier public key") {
			t.Fatalf("expected embedded key write failure, got %v", err)
		}
	})
}

func TestRunSign_Errors(t *testing.T) {
	tmp := t.TempDir()
	profileDir := filepath.Join(tmp, "profile")
	writeTestFile(t, filepath.Join(profileDir, "profile.json"), []byte(`{}`))

	withChdir(t, tmp, func() {
		if err := runSign([]string{"--private-key", "keys/private.pem"}); err == nil {
			t.Fatal("expected missing profile-dir error")
		}
		if err := runSign([]string{"--profile-dir", profileDir, "--private-key", "keys/private.pem", "extra"}); err == nil {
			t.Fatal("expected positional-args error from runSign")
		}
		if err := runSign([]string{"--unknown"}); err == nil {
			t.Fatal("expected flag parse error from runSign")
		}
		if err := runSign([]string{"--profile-dir", profileDir, "--private-key", "no-such-key.pem"}); err == nil {
			t.Fatal("expected missing private key error")
		}
	})
}

func TestRunSign_BuildManifestError(t *testing.T) {
	tmp := t.TempDir()
	withChdir(t, tmp, func() {
		if err := runKeygen([]string{
			"--private-out", "keys/private.pem",
			"--public-out", "keys/public.pem",
		}); err != nil {
			t.Fatalf("runKeygen failed: %v", err)
		}

		err := runSign([]string{
			"--profile-dir", filepath.Join(tmp, "missing-profile"),
			"--private-key", filepath.Join(tmp, "keys/private.pem"),
		})
		if err == nil || !strings.Contains(err.Error(), "build profile manifest") {
			t.Fatalf("expected build profile manifest error, got %v", err)
		}
	})
}

func TestRunSign_WriteFailures(t *testing.T) {
	tmp := t.TempDir()
	profileDir := filepath.Join(tmp, "profile")
	writeTestFile(t, filepath.Join(profileDir, "profile.json"), []byte(`{}`))

	withChdir(t, tmp, func() {
		if err := runKeygen([]string{
			"--private-out", "keys/private.pem",
			"--public-out", "keys/public.pem",
		}); err != nil {
			t.Fatalf("runKeygen failed: %v", err)
		}

		if err := runSign([]string{
			"--profile-dir", profileDir,
			"--private-key", filepath.Join(tmp, "keys/private.pem"),
			"--manifest-out", "/dev/null/manifest.json",
		}); err == nil {
			t.Fatal("expected manifest write failure")
		}

		if err := runSign([]string{
			"--profile-dir", profileDir,
			"--private-key", filepath.Join(tmp, "keys/private.pem"),
			"--sig-out", "/dev/null/manifest.sig",
		}); err == nil {
			t.Fatal("expected signature write failure")
		}
	})
}

func TestLoadEd25519PrivateKey_Errors(t *testing.T) {
	tmp := t.TempDir()

	missing := filepath.Join(tmp, "missing.pem")
	if _, err := loadEd25519PrivateKey(missing); err == nil {
		t.Fatal("expected missing-key error")
	}

	invalid := filepath.Join(tmp, "invalid.pem")
	writeTestFile(t, invalid, []byte("not pem"))
	if _, err := loadEd25519PrivateKey(invalid); err == nil {
		t.Fatal("expected invalid PEM error")
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	rsaDER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("marshal RSA key: %v", err)
	}
	rsaPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaDER})
	rsaPath := filepath.Join(tmp, "rsa.pem")
	writeTestFile(t, rsaPath, rsaPEM)
	if _, err := loadEd25519PrivateKey(rsaPath); err == nil {
		t.Fatal("expected non-ed25519 private key error")
	}

	badPKCS8 := filepath.Join(tmp, "badpkcs8.pem")
	writeTestFile(t, badPKCS8, pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: []byte("bad-der"),
	}))
	if _, err := loadEd25519PrivateKey(badPKCS8); err == nil || !strings.Contains(err.Error(), "as PKCS8") {
		t.Fatalf("expected PKCS8 parse error, got %v", err)
	}
}

func TestWriteFileWithPerm_Error(t *testing.T) {
	tmp := t.TempDir()
	fileAsDir := filepath.Join(tmp, "not-dir")
	writeTestFile(t, fileAsDir, []byte("x"))

	err := writeFileWithPerm(filepath.Join(fileAsDir, "child.txt"), []byte("data"), 0o644)
	if err == nil {
		t.Fatal("expected writeFileWithPerm to fail when parent path is not a directory")
	}

	dirPath := filepath.Join(tmp, "dir-target")
	if err := os.MkdirAll(dirPath, 0o755); err != nil {
		t.Fatalf("mkdir dir-target: %v", err)
	}
	if err := writeFileWithPerm(dirPath, []byte("data"), 0o644); err == nil {
		t.Fatal("expected writeFileWithPerm to fail when target path is a directory")
	}
}

func TestBuildManifestHelpers_Errors(t *testing.T) {
	tmp := t.TempDir()

	if _, err := buildProfileManifest(filepath.Join(tmp, "missing")); err == nil {
		t.Fatal("expected buildProfileManifest to fail for missing directory")
	}

	symlinkDir := filepath.Join(tmp, "symlink-profile")
	if err := os.MkdirAll(symlinkDir, 0o755); err != nil {
		t.Fatalf("mkdir symlink profile: %v", err)
	}
	target := filepath.Join(symlinkDir, "target.txt")
	writeTestFile(t, target, []byte("x"))
	link := filepath.Join(symlinkDir, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	if _, err := collectProfileHashes(symlinkDir); err == nil {
		t.Fatal("expected collectProfileHashes to fail on non-regular file (symlink)")
	}

	includeDir := filepath.Join(tmp, "include-manifest")
	writeTestFile(t, filepath.Join(includeDir, manifestFileName), []byte("{}"))
	writeTestFile(t, filepath.Join(includeDir, manifestSigName), []byte("abc"))
	writeTestFile(t, filepath.Join(includeDir, overridesFileName), []byte(`{"ssh_port": 2222}`))
	writeTestFile(t, filepath.Join(includeDir, "x.txt"), []byte("x"))
	hashes, err := collectProfileHashes(includeDir)
	if err != nil {
		t.Fatalf("collectProfileHashes include-manifest failed: %v", err)
	}
	if len(hashes) != 1 || hashes["x.txt"] == "" {
		t.Fatalf("expected only x.txt to be hashed, got %#v", hashes)
	}

	unreadableDir := filepath.Join(tmp, "unreadable")
	if err := os.MkdirAll(unreadableDir, 0o755); err != nil {
		t.Fatalf("mkdir unreadable: %v", err)
	}
	unreadableFile := filepath.Join(unreadableDir, "secret.txt")
	writeTestFile(t, unreadableFile, []byte("secret"))
	if err := os.Chmod(unreadableFile, 0o000); err != nil {
		t.Fatalf("chmod unreadable file: %v", err)
	}
	defer os.Chmod(unreadableFile, 0o644)
	if _, err := collectProfileHashes(unreadableDir); err == nil {
		t.Fatal("expected collectProfileHashes to fail on unreadable regular file")
	}

	if _, err := sha256File(filepath.Join(tmp, "missing.txt")); err == nil {
		t.Fatal("expected sha256File to fail for missing file")
	}
	if _, err := sha256File(tmp); err == nil {
		t.Fatal("expected sha256File to fail when hashing a directory")
	}
}

func withChdir(t *testing.T, dir string, fn func()) {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd failed: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir to %q failed: %v", dir, err)
	}
	defer func() {
		if err := os.Chdir(wd); err != nil {
			t.Fatalf("restore cwd failed: %v", err)
		}
	}()

	fn()
}

func parseEd25519PrivateKeyFromPEM(t *testing.T, path string) ed25519.PrivateKey {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read private key %q: %v", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("private key %q is not valid PEM", path)
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse private key %q as PKCS8: %v", path, err)
	}
	key, ok := keyAny.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("private key %q is not Ed25519", path)
	}
	return key
}

func parseEd25519PublicKeyFromPEM(t *testing.T, path string) ed25519.PublicKey {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read public key %q: %v", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("public key %q is not valid PEM", path)
	}
	keyAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse public key %q as PKIX: %v", path, err)
	}
	key, ok := keyAny.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("public key %q is not Ed25519", path)
	}
	return key
}

func assertFileExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected file to exist %q: %v", path, err)
	}
}

func mustStat(t *testing.T, path string) os.FileInfo {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %q: %v", path, err)
	}
	return fi
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
