package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/tpm2-trust/assh/hostkey"
	"github.com/tpm2-trust/assh/sandbox"
)

// A secret - a PIN, a lockout authorization - comes from a file descriptor
// or the terminal, never from argv or the environment: both are readable
// by other processes (/proc/PID/cmdline, /proc/PID/environ).

const maxSecret = 1024

// lockForSecret keeps the process out of swap and core files before the first
// secret is read: nothing is locked for a command that never reads one. Root
// is stopped by a lock it cannot take. A user with a limit on locked memory, the
// usual case (and the tests'), goes on: it is said, and it is theirs to raise.
var lockForSecret = sync.OnceValue(func() error {
	err := sandbox.LockMemory()
	if err != nil && os.Geteuid() != 0 {
		fmt.Fprintf(os.Stderr, "assh: this secret can reach swap: %v\n", err)
		return nil
	}
	return err
})

// readSecret reads a secret from fd, every byte to its end and nothing
// stripped (printf '%s' "$PIN", not echo); with fd < 0 from the terminal,
// without echo, one line. confirm asks the terminal twice.
func readSecret(fd int, prompt string, confirm bool) ([]byte, error) {
	if err := lockForSecret(); err != nil {
		return nil, fmt.Errorf("not reading the %s: %w", prompt, err)
	}
	if fd >= 0 {
		f := os.NewFile(uintptr(fd), fmt.Sprintf("fd %d", fd))
		if f == nil {
			return nil, fmt.Errorf("no file descriptor %d", fd)
		}
		defer f.Close()
		// One buffer of the final size: no growing slice leaves earlier copies.
		b := make([]byte, maxSecret+1)
		n, err := io.ReadFull(f, b)
		switch {
		case n > maxSecret:
			clear(b)
			return nil, fmt.Errorf("fd %d: more than %d bytes", fd, maxSecret)
		case err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF):
			clear(b)
			return nil, fmt.Errorf("reading the %s from fd %d: %w", prompt, fd, err)
		}
		return b[:n], nil
	}
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("no terminal to ask for the %s (or give it on a file descriptor): %w", prompt, err)
	}
	defer tty.Close()
	b, err := askTerminal(tty, prompt+": ")
	if err != nil || !confirm {
		return b, err
	}
	again, err := askTerminal(tty, prompt+" again: ")
	defer clear(again)
	if err != nil {
		clear(b)
		return nil, err
	}
	if !bytes.Equal(b, again) {
		clear(b)
		return nil, fmt.Errorf("the two %ss differ", prompt)
	}
	return b, nil
}

// askTerminal reads one line from tty with its echo off.
func askTerminal(tty *os.File, prompt string) ([]byte, error) {
	fd := int(tty.Fd())
	old, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return nil, fmt.Errorf("the terminal: %w", err)
	}
	noEcho := *old
	noEcho.Lflag &^= unix.ECHO
	noEcho.Lflag |= unix.ICANON | unix.ECHONL
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &noEcho); err != nil {
		return nil, fmt.Errorf("the terminal: %w", err)
	}
	defer unix.IoctlSetTermios(fd, unix.TCSETS, old)
	if _, err := tty.WriteString(prompt); err != nil {
		return nil, err
	}
	line := make([]byte, 0, maxSecret)
	buf := make([]byte, 1)
	defer clear(buf)
	for {
		n, err := tty.Read(buf)
		if n == 1 {
			if buf[0] == '\n' {
				return line, nil
			}
			if len(line) == maxSecret {
				clear(line)
				return nil, fmt.Errorf("more than %d bytes", maxSecret)
			}
			line = append(line, buf[0])
		}
		if err != nil {
			clear(line)
			if errors.Is(err, io.EOF) {
				return nil, errors.New("no line on the terminal")
			}
			return nil, err
		}
	}
}

// pinSource gives a command's PIN: read once, when the TPM first needs it,
// then the same for every later use in the command. wipe clears it.
type pinSource struct {
	fd      int
	prompt  string
	confirm bool
	pin     []byte
}

func (p *pinSource) get() ([]byte, error) {
	if p.pin == nil {
		b, err := readSecret(p.fd, p.prompt, p.confirm)
		if err != nil {
			return nil, err
		}
		if err := hostkey.CheckPIN(b); err != nil {
			clear(b)
			return nil, err
		}
		p.pin = b
	}
	return append([]byte(nil), p.pin...), nil
}

func (p *pinSource) wipe() { clear(p.pin) }
