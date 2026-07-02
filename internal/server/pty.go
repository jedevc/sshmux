package server

import (
	"os"

	"github.com/charmbracelet/ssh"
	creackpty "github.com/creack/pty"
)

type ptyRequestKey struct {
	session ssh.Session
}

func WithPtyRequests() ssh.Option {
	return func(srv *ssh.Server) error {
		srv.PtyHandler = func(ctx ssh.Context, s ssh.Session, pty ssh.Pty) (func() error, error) {
			// Proxy routes need the client's PTY metadata so it can be forwarded to
			// the backend, but they must not allocate an intermediate PTY or use
			// ssh.EmulatePty(), which rewrites output newlines and breaks transparent
			// terminal proxying. Local run.pty routes allocate their own PTY later.
			key := ptyRequestKey{session: s}
			ctx.SetValue(key, pty)
			return func() error {
				ctx.SetValue(key, nil)
				return nil
			}, nil
		}
		return nil
	}
}

func sessionPty(s ssh.Session) (ssh.Pty, <-chan ssh.Window, bool) {
	pty, winCh, ok := s.Pty()
	if ok {
		return pty, winCh, true
	}
	pty, ok = s.Context().Value(ptyRequestKey{session: s}).(ssh.Pty)
	if !ok {
		return ssh.Pty{}, winCh, false
	}
	return pty, winCh, true
}

func ptyWindowSize(win ssh.Window) *creackpty.Winsize {
	return &creackpty.Winsize{
		Rows: uint16(win.Height),
		Cols: uint16(win.Width),
		X:    uint16(win.WidthPixels),
		Y:    uint16(win.HeightPixels),
	}
}

func resizePty(ptyFile *os.File, winCh <-chan ssh.Window, done <-chan struct{}) {
	for {
		select {
		case win, ok := <-winCh:
			if !ok {
				return
			}
			_ = creackpty.Setsize(ptyFile, ptyWindowSize(win))
		case <-done:
			return
		}
	}
}
