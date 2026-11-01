package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tpm2-trust/assh/internal/swtpmtest"
)

// shortOpen makes openTPM's wait short for a test.
func shortOpen(t *testing.T) {
	a, w, r := openAttempts, openWait, openRetry
	t.Cleanup(func() { openAttempts, openWait, openRetry = a, w, r })
	openAttempts, openWait, openRetry = 3, 300*time.Millisecond, 20*time.Millisecond
}

// A TPM that never appears is an error, after every attempt.
func TestOpenTPMAbsent(t *testing.T) {
	shortOpen(t)
	path := filepath.Join(t.TempDir(), "tpmrm0")
	start := time.Now()
	_, err := openTPM(path)()
	if err == nil {
		t.Fatal("a TPM that is not there opened")
	}
	if !strings.Contains(err.Error(), "attempts") || time.Since(start) < openWait {
		t.Fatalf("given up early (%s): %v", time.Since(start), err)
	}
}

// A TPM that appears while openTPM waits is taken.
func TestOpenTPMLate(t *testing.T) {
	shortOpen(t)
	openWait = 5 * time.Second
	sw := swtpmtest.Start(t)
	path := filepath.Join(t.TempDir(), "tpmrm0")
	go func() {
		time.Sleep(100 * time.Millisecond)
		os.Symlink(sw.Sock, path)
	}()
	tpm, err := openTPM(path)()
	if err != nil {
		t.Fatal(err)
	}
	tpm.Close()
}
