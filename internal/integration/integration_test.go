// SPDX-License-Identifier: GPL-3.0-only

package integration

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var (
	binaryPath string
	repoRoot   string
)

func TestMain(m *testing.M) {
	if os.Getenv("CW_INTEGRATION") != "1" {
		os.Exit(m.Run())
	}
	_, file, _, _ := runtime.Caller(0)
	repoRoot = filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	directory, err := os.MkdirTemp("", "cw-integration-*")
	if err != nil {
		panic(err)
	}
	binaryPath = filepath.Join(directory, "cw")
	build := exec.Command("go", "build", "-o", binaryPath, "./cmd/cw")
	build.Dir = repoRoot
	build.Stdout = os.Stdout
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		panic(err)
	}
	code := m.Run()
	_ = os.RemoveAll(directory)
	os.Exit(code)
}

func requireIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("CW_INTEGRATION") != "1" {
		t.Skip("set CW_INTEGRATION=1 to run OpenSSL integration tests")
	}
}

func run(t *testing.T, args ...string) string {
	t.Helper()
	command := exec.Command(binaryPath, args...)
	command.Dir = repoRoot
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("cw %s failed: %v\n%s", strings.Join(args, " "), err, output)
	}
	return string(output)
}

func mustFail(t *testing.T, args ...string) string {
	t.Helper()
	command := exec.Command(binaryPath, args...)
	command.Dir = repoRoot
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("cw %s unexpectedly succeeded\n%s", strings.Join(args, " "), output)
	}
	return string(output)
}

func writeFile(t *testing.T, path, value string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), mode); err != nil {
		t.Fatal(err)
	}
}

func assertSameFile(t *testing.T, first, second string) {
	t.Helper()
	firstValue, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	secondValue, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstValue, secondValue) {
		t.Fatalf("%s and %s differ", first, second)
	}
}

func TestRSAKeySignAndCMS(t *testing.T) {
	requireIntegration(t)
	directory := t.TempDir()
	message := filepath.Join(directory, "message.txt")
	key := filepath.Join(directory, "rsa.key.pem")
	publicKey := filepath.Join(directory, "rsa.pub.pem")
	certificate := filepath.Join(directory, "rsa.crt.pem")
	signature := filepath.Join(directory, "message.sig")
	encrypted := filepath.Join(directory, "message.cms")
	decrypted := filepath.Join(directory, "message.out")
	writeFile(t, message, "classical integration test\n", 0o600)

	run(t, "keygen", "rsa", "--no-passphrase", "--out", key, "--public-out", publicKey)
	run(t, "sign", "--no-passphrase", "--key", key, "--in", message, "--out", signature)
	run(t, "verify", "--key", publicKey, "--in", message, "--signature", signature)
	run(t, "certgen", "--no-passphrase", "--key", key, "--subject", "/CN=Integration-RSA",
		"--days", "1", "--out", certificate)
	run(t, "encrypt", "--in", message, "--out", encrypted, "--recipient", certificate)
	run(t, "decrypt", "--no-passphrase", "--in", encrypted, "--out", decrypted,
		"--cert", certificate, "--key", key)
	assertSameFile(t, message, decrypted)
}

func TestPostQuantumRecipientAndSignature(t *testing.T) {
	requireIntegration(t)
	algorithms := run(t, "algorithms", "keys", "--all")
	if !strings.Contains(algorithms, "ML-KEM-768") || !strings.Contains(algorithms, "ML-DSA-65") {
		t.Skip("OpenSSL provider does not expose ML-KEM-768 and ML-DSA-65")
	}
	directory := t.TempDir()
	message := filepath.Join(directory, "message.txt")
	caKey := filepath.Join(directory, "ca.key.pem")
	caPublic := filepath.Join(directory, "ca.pub.pem")
	caCert := filepath.Join(directory, "ca.crt.pem")
	kemKey := filepath.Join(directory, "kem.key.pem")
	kemPublic := filepath.Join(directory, "kem.pub.pem")
	kemCert := filepath.Join(directory, "kem.crt.pem")
	signature := filepath.Join(directory, "message.sig")
	encrypted := filepath.Join(directory, "message.cms")
	decrypted := filepath.Join(directory, "message.out")
	writeFile(t, message, "post-quantum integration test\n", 0o600)

	run(t, "keygen", "ml-dsa-65", "--no-passphrase", "--out", caKey, "--public-out", caPublic)
	run(t, "sign", "--no-passphrase", "--key", caKey, "--in", message, "--out", signature)
	run(t, "verify", "--key", caPublic, "--in", message, "--signature", signature)
	run(t, "certgen", "--no-passphrase", "--key", caKey, "--subject", "/CN=Integration-PQ-CA",
		"--days", "1", "--out", caCert)
	run(t, "keygen", "ml-kem-768", "--no-passphrase", "--out", kemKey, "--public-out", kemPublic)
	run(t, "certissue", "--no-passphrase", "--ca-cert", caCert, "--ca-key", caKey,
		"--public-key", kemPublic, "--subject", "/CN=Integration-PQ-Recipient",
		"--days", "1", "--out", kemCert)
	run(t, "encrypt", "--in", message, "--out", encrypted, "--recipient", kemCert)
	run(t, "decrypt", "--no-passphrase", "--in", encrypted, "--out", decrypted,
		"--cert", kemCert, "--key", kemKey)
	assertSameFile(t, message, decrypted)
}

func TestSymmetricPasswordAndTamperFailures(t *testing.T) {
	requireIntegration(t)
	directory := t.TempDir()
	message := filepath.Join(directory, "message.txt")
	key := filepath.Join(directory, "aes.key")
	passphrase := filepath.Join(directory, "passphrase")
	wrongPassphrase := filepath.Join(directory, "wrong-passphrase")
	symmetricCMS := filepath.Join(directory, "symmetric.cms")
	symmetricOutput := filepath.Join(directory, "symmetric.out")
	passwordCMS := filepath.Join(directory, "password.cms")
	passwordOutput := filepath.Join(directory, "password.out")
	wrongOutput := filepath.Join(directory, "wrong.out")
	writeFile(t, message, "authenticated CMS integration test\n", 0o600)
	writeFile(t, passphrase, "correct horse battery staple\n", 0o600)
	writeFile(t, wrongPassphrase, "wrong password\n", 0o600)

	run(t, "symkey", "aes-256", "--out", key)
	run(t, "sym-encrypt", "--key", key, "--in", message, "--out", symmetricCMS)
	run(t, "sym-decrypt", "--key", key, "--in", symmetricCMS, "--out", symmetricOutput)
	assertSameFile(t, message, symmetricOutput)
	run(t, "pass-encrypt", "--passphrase-file", passphrase, "--in", message, "--out", passwordCMS)
	run(t, "pass-decrypt", "--passphrase-file", passphrase, "--in", passwordCMS, "--out", passwordOutput)
	assertSameFile(t, message, passwordOutput)

	failure := mustFail(t, "pass-decrypt", "--passphrase-file", wrongPassphrase,
		"--in", passwordCMS, "--out", wrongOutput)
	if !strings.Contains(failure, "decryption failed") {
		t.Fatalf("unexpected failure: %s", failure)
	}
	if _, err := os.Stat(wrongOutput); !os.IsNotExist(err) {
		t.Fatalf("failed decryption left output file: %v", err)
	}

	tampered := filepath.Join(directory, "tampered.cms")
	value, err := os.ReadFile(symmetricCMS)
	if err != nil {
		t.Fatal(err)
	}
	value[len(value)-1] ^= 0x01
	if err := os.WriteFile(tampered, value, 0o600); err != nil {
		t.Fatal(err)
	}
	tamperedOutput := filepath.Join(directory, "tampered.out")
	mustFail(t, "sym-decrypt", "--key", key, "--in", tampered, "--out", tamperedOutput)
	if _, err := os.Stat(tamperedOutput); !os.IsNotExist(err) {
		t.Fatalf("tampered decryption left output file: %v", err)
	}
}

func TestX25519Derive(t *testing.T) {
	requireIntegration(t)
	directory := t.TempDir()
	aKey := filepath.Join(directory, "a.key.pem")
	aPublic := filepath.Join(directory, "a.pub.pem")
	bKey := filepath.Join(directory, "b.key.pem")
	bPublic := filepath.Join(directory, "b.pub.pem")
	ab := filepath.Join(directory, "ab.secret")
	ba := filepath.Join(directory, "ba.secret")

	run(t, "keygen", "x25519", "--no-passphrase", "--out", aKey, "--public-out", aPublic)
	run(t, "keygen", "x25519", "--no-passphrase", "--out", bKey, "--public-out", bPublic)
	run(t, "derive", "--no-passphrase", "--key", aKey, "--peer-key", bPublic, "--out", ab)
	run(t, "derive", "--no-passphrase", "--key", bKey, "--peer-key", aPublic, "--out", ba)
	assertSameFile(t, ab, ba)
}
