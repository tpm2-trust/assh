package server

import (
	"encoding/json"
	"io"
	"net"
	"sync"

	"golang.org/x/sys/unix"
)

// The descriptors the server hands to its unprivileged half
// (exec.Cmd.ExtraFiles).
const (
	childListenFD  = 3 // the listening TCP socket
	childControlFD = 4 // SOCK_SEQPACKET to the server
)

// msg is one message on the control socket, either way.
type msg struct {
	// init, ready, log, sign, signed, session, resize, ended
	T string `json:"t"`

	ID   uint64 `json:"id,omitempty"`   // sign/signed; session, resize, ended: the session
	Data []byte `json:"data,omitempty"` // sign: what to sign; signed: the signature blob

	Algorithm string `json:"algorithm,omitempty"` // sign: the algorithm negotiated, "" the key's own
	Format    string `json:"format,omitempty"`    // signed: the signature's format
	Text      string `json:"text,omitempty"`      // log, ready: for the log
	Err       string `json:"err,omitempty"`       // signed

	// session: who logged in and their terminal; resize: its new size.
	User   string `json:"user,omitempty"`
	Key    string `json:"key,omitempty"`
	Remote string `json:"remote,omitempty"`
	Term   string `json:"term,omitempty"`
	Cols   int    `json:"cols,omitempty"`
	Rows   int    `json:"rows,omitempty"`

	// init
	HostKey        []byte   `json:"host_key,omitempty"` // the public key, SSH wire format
	Algorithms     []string `json:"algorithms,omitempty"`
	AuthorizedKeys []string `json:"authorized_keys,omitempty"`
	Version        string   `json:"version,omitempty"`
	Name           string   `json:"name,omitempty"`
	Notice         string   `json:"notice,omitempty"`
}

// conn is the control socket, with messages and descriptors.
type conn struct {
	c  *net.UnixConn
	mu sync.Mutex
}

func (s *conn) send(m msg, fd int) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	var oob []byte
	if fd >= 0 {
		oob = unix.UnixRights(fd)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _, err = s.c.WriteMsgUnix(b, oob, nil)
	return err
}

// recv reads one message, and the descriptor that came with it (-1: none).
func (s *conn) recv() (msg, int, error) {
	buf := make([]byte, 1<<20)
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := s.c.ReadMsgUnix(buf, oob)
	if err != nil {
		return msg{}, -1, err
	}
	if n == 0 {
		return msg{}, -1, io.EOF
	}
	fd := -1
	if oobn > 0 {
		if cmsgs, err := unix.ParseSocketControlMessage(oob[:oobn]); err == nil {
			for _, cm := range cmsgs {
				if fds, err := unix.ParseUnixRights(&cm); err == nil {
					for i, f := range fds {
						if i == 0 && fd < 0 {
							fd = f
						} else {
							unix.Close(f)
						}
					}
				}
			}
		}
	}
	var m msg
	if err := json.Unmarshal(buf[:n], &m); err != nil {
		if fd >= 0 {
			unix.Close(fd)
		}
		return msg{}, -1, err
	}
	return m, fd, nil
}
