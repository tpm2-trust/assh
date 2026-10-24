package server

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

// RunCommand runs a command for a session, as OpenSSH's ForceCommand
// does: in a new pseudo-terminal when the client asked for one, else on
// pipes, with the session's sizes passed on. It returns when the command
// has ended and closes the session. cred runs it as another user (nil:
// as this process); env is its environment, to which the session's TERM
// and ASSH_USER, ASSH_KEY and ASSH_REMOTE are added.
func RunCommand(s *Session, argv []string, cred *syscall.Credential, env []string) error {
	defer s.Close()
	if len(argv) == 0 {
		return errors.New("no command")
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = append(append([]string(nil), env...),
		"ASSH_USER="+s.User, "ASSH_KEY="+s.Key, "ASSH_REMOTE="+s.Remote)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Credential: cred}
	if s.Term == "" {
		// Not cmd.Stdin = s: Wait would wait for the client to stop
		// typing, not for the command.
		stdin, err := cmd.StdinPipe()
		if err != nil {
			return err
		}
		cmd.Stdout, cmd.Stderr = s, s
		if err := cmd.Start(); err != nil {
			return err
		}
		go io.Copy(stdin, s)
		return cmd.Wait()
	}
	cmd.Env = append(cmd.Env, "TERM="+s.Term)
	master, slave, err := openPTY()
	if err != nil {
		return fmt.Errorf("a pseudo-terminal: %w", err)
	}
	defer master.Close()
	setSize(master, s.Cols, s.Rows)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr.Setctty = true
	cmd.SysProcAttr.Ctty = 0 // the child's stdin
	err = cmd.Start()
	slave.Close()
	if err != nil {
		return err
	}
	done := make(chan struct{})
	go func() {
		for {
			select {
			case size := <-s.Resized():
				setSize(master, size[0], size[1])
			case <-done:
				return
			}
		}
	}()
	go io.Copy(master, s)
	io.Copy(s, master) // ends with EIO once the command and its children are gone
	err = cmd.Wait()
	close(done)
	return err
}

// openPTY opens a new pseudo-terminal pair.
func openPTY() (master, slave *os.File, err error) {
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	if err := unix.IoctlSetPointerInt(int(m.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		m.Close()
		return nil, nil, err
	}
	n, err := unix.IoctlGetInt(int(m.Fd()), unix.TIOCGPTN)
	if err != nil {
		m.Close()
		return nil, nil, err
	}
	s, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		m.Close()
		return nil, nil, err
	}
	return m, s, nil
}

func setSize(f *os.File, cols, rows int) {
	if cols <= 0 || rows <= 0 {
		return
	}
	unix.IoctlSetWinsize(int(f.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Col: uint16(cols), Row: uint16(rows)})
}
