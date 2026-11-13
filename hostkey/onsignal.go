package hostkey

import (
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/google/go-tpm/tpm2/transport"
)

// SignalClose closes the CA when the process is told to end while it may be
// open: from before the TPM is opened until the caller's own close has run.
// A signal's default action ends a Go program without running its defers,
// so a close in a defer alone leaves the CA open for the rest of the boot.
//
//	g := hostkey.CloseOnSignal(open, log)
//	defer g.Stop()
//	tpm, err := open()
//	tpm = g.TPM(tpm)
//	defer hostkey.Close(tpm)
//
// On SIGTERM, SIGINT or SIGHUP it closes (Close) and exits with 128 plus
// the signal's number. It closes through the TPM the caller uses (TPM), one
// command at a time between the caller's - a device that opens once
// (/dev/tpm0) has no second way in -, and through open before the caller
// has one.
type SignalClose struct {
	open func() (transport.TPMCloser, error)
	log  func(string)
	exit func(int)
	ch   chan os.Signal
	done chan struct{}

	mu  sync.Mutex
	tpm *lockedTPM
}

// CloseOnSignal starts it. open opens the TPM for a signal that comes
// before the caller has opened it; log says what was done.
func CloseOnSignal(open func() (transport.TPMCloser, error), log func(string)) *SignalClose {
	g := &SignalClose{open: open, log: log, exit: os.Exit, ch: make(chan os.Signal, 1), done: make(chan struct{})}
	signal.Notify(g.ch, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	go g.wait()
	return g
}

func (g *SignalClose) wait() {
	select {
	case <-g.done:
		return
	case sig := <-g.ch:
		g.log("signal " + sig.String() + ": closing the CA before the end")
		code := 128
		if n, ok := sig.(syscall.Signal); ok {
			code += int(n)
		}
		if err := g.close(); err != nil {
			g.log("THE CA IS NOT CLOSED: " + err.Error())
		}
		g.exit(code)
	}
}

func (g *SignalClose) close() error {
	g.mu.Lock()
	t := g.tpm
	g.mu.Unlock()
	if t == nil {
		own, err := g.open()
		if err != nil {
			// The caller may have opened it meanwhile, a device that opens once.
			g.mu.Lock()
			t = g.tpm
			g.mu.Unlock()
			if t == nil {
				return err
			}
		} else {
			defer own.Close()
			res, err := Close(own)
			if err != nil {
				return err
			}
			g.log(res.String() + ": the CA signs nothing more until the next boot")
			return nil
		}
	}
	res, err := Close(t)
	if err != nil {
		return err
	}
	g.log(res.String() + ": the CA signs nothing more until the next boot")
	return nil
}

// TPM is t for the caller's use from here on: the same TPM, a command at a
// time, so that a signal's close goes between the caller's commands.
func (g *SignalClose) TPM(t transport.TPMCloser) transport.TPMCloser {
	l := &lockedTPM{t: t}
	g.mu.Lock()
	g.tpm = l
	g.mu.Unlock()
	return l
}

// Stop ends it, once the caller's own close has run: signals are the
// caller's again.
func (g *SignalClose) Stop() {
	signal.Stop(g.ch)
	select {
	case <-g.done:
	default:
		close(g.done)
	}
}

type lockedTPM struct {
	mu sync.Mutex
	t  transport.TPMCloser
}

func (l *lockedTPM) Send(input []byte) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.t.Send(input)
}

func (l *lockedTPM) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.t.Close()
}
