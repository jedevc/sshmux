package server

import (
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/charmbracelet/ssh"
	creackpty "github.com/creack/pty"
)

// runCmd executes the configured command for the session.
func runCmd(s ssh.Session, command string, withPTY bool) error {
	cmd := exec.CommandContext(s.Context(), "sh", "-c", command)
	cmd.Env = append(os.Environ(), s.Environ()...)

	if withPTY {
		ptyReq, winCh, ok := sessionPty(s)
		if !ok {
			return fmt.Errorf("pty requested but client did not allocate one")
		}
		cmd.Env = append(cmd.Env, "TERM="+ptyReq.Term)
		ptyFile, err := creackpty.StartWithSize(cmd, ptyWindowSize(ptyReq.Window))
		if err != nil {
			return fmt.Errorf("start pty cmd: %w", err)
		}

		done := make(chan struct{})
		defer close(done)
		go resizePty(ptyFile, winCh, done)

		go func() {
			_, _ = io.Copy(ptyFile, s)
		}()

		outputDone := make(chan struct{})
		go func() {
			defer close(outputDone)
			_, _ = io.Copy(s, ptyFile)
		}()

		waitErr := cmd.Wait()
		<-outputDone
		_ = ptyFile.Close()
		return waitErr
	}

	cmd.Stdin = s
	cmd.Stdout = s
	cmd.Stderr = s.Stderr()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start cmd: %w", err)
	}
	return cmd.Wait()
}
