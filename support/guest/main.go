package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/charmbracelet/ssh"
	gossh "golang.org/x/crypto/ssh"
)

const (
	listenAddr              = ":2222"
	defaultShell            = "/bin/sh"
	defaultHome             = "/home/user"
	defaultGuestIdleTimeout = time.Minute
)

var (
	idleMu         sync.Mutex
	idleTimer      *time.Timer
	idleGeneration int
	activeSession  int
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	server := &ssh.Server{
		Addr:             listenAddr,
		PublicKeyHandler: allowMuxKey,
		Handler:          handleSession,
	}
	if err := ssh.AllocatePty()(server); err != nil {
		fatalf("enable pty allocation: %v", err)
	}
	server.AddHostKey(guestHostKey)
	startIdleTimer()

	slog.Info("guest listening",
		"addr", listenAddr,
		"idle_timeout", guestIdleTimeout,
		"shell", guestShell,
		"home", guestHome,
		"allow_fingerprint", gossh.FingerprintSHA256(guestAllowKey),
	)
	if err := server.ListenAndServe(); err != nil {
		fatalf("listen: %v", err)
	}
}

func allowMuxKey(_ ssh.Context, key ssh.PublicKey) bool {
	allowed := ssh.KeysEqual(key, guestAllowKey)
	slog.Info("auth public key",
		"fingerprint", gossh.FingerprintSHA256(key),
		"allowed", allowed,
	)
	return allowed
}

func startIdleTimer() {
	idleMu.Lock()
	defer idleMu.Unlock()
	resetIdleTimerLocked()
}

func sessionStarted() {
	idleMu.Lock()
	defer idleMu.Unlock()
	activeSession++
	idleGeneration++
	if idleTimer != nil {
		idleTimer.Stop()
	}
}

func sessionFinished() {
	idleMu.Lock()
	defer idleMu.Unlock()
	activeSession--
	if activeSession <= 0 {
		activeSession = 0
		resetIdleTimerLocked()
	}
}

func resetIdleTimerLocked() {
	if idleTimer != nil {
		idleTimer.Stop()
	}
	idleGeneration++
	generation := idleGeneration
	idleTimer = time.AfterFunc(guestIdleTimeout, func() {
		idleMu.Lock()
		defer idleMu.Unlock()
		if activeSession == 0 && generation == idleGeneration {
			slog.Info("guest idle timeout reached", "timeout", guestIdleTimeout)
			os.Exit(0)
		}
	})
}

func handleSession(s ssh.Session) {
	sessionStarted()
	defer sessionFinished()

	ptyReq, _, isPTY := s.Pty()

	slog.Info("session start",
		"user", s.User(),
		"remote", s.RemoteAddr(),
		"raw_command", s.RawCommand(),
		"pty", isPTY,
	)
	if isPTY {
		slog.Info("session pty request",
			"term", ptyReq.Term,
			"height", ptyReq.Window.Height,
			"width", ptyReq.Window.Width,
			"tty", ptyReq.Name(),
			"modes", terminalModesString(ptyReq.Modes),
		)
	}

	args := []string{"-l"}
	if isPTY {
		args = []string{"-li"}
	}
	cmd := exec.Command(guestShell, args...)
	cmd.Env = buildEnv(ptyReq.Term)
	if isPTY {
		cmd.Env = append(cmd.Env, "SSH_TTY="+ptyReq.Name())
	}
	if rawCmd := s.RawCommand(); rawCmd != "" && !isPTY {
		cmd = exec.Command(guestShell, "-lc", rawCmd)
		cmd.Env = buildEnv("")
	}

	var sessionErr error
	if isPTY {
		sessionErr = runWithPTY(s, cmd, ptyReq)
	} else {
		sessionErr = runDirect(s, cmd)
	}
	if sessionErr != nil && !isExpectedExit(sessionErr) {
		slog.Error("session error", "user", s.User(), "err", sessionErr)
	}
	slog.Info("session end", "user", s.User(), "remote", s.RemoteAddr(), "err", sessionErr)
}

func buildEnv(term string) []string {
	env := os.Environ()
	if term != "" {
		env = append(env, "TERM="+term)
	}
	env = append(env, "HOME="+guestHome)
	return env
}

func runWithPTY(s ssh.Session, cmd *exec.Cmd, ptyReq ssh.Pty) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid:  true,
		Setctty: true,
		Ctty:    0,
	}
	slog.Info("starting pty command",
		"path", cmd.Path,
		"args", cmd.Args,
		"tty", ptyReq.Name(),
		"setsid", cmd.SysProcAttr.Setsid,
		"setctty", cmd.SysProcAttr.Setctty,
		"ctty", cmd.SysProcAttr.Ctty,
	)
	if err := ptyReq.Start(cmd); err != nil {
		slog.Error("start pty command failed", "err", err)
		_, _ = fmt.Fprintf(s.Stderr(), "start shell: %v\n", err)
		_ = s.Exit(1)
		return err
	}
	slog.Info("pty command started", "pid", cmd.Process.Pid)

	waitErr := cmd.Wait()
	slog.Info("pty command exited", "err", waitErr)
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			_ = s.Exit(exitErr.ExitCode())
			return nil
		}
		_ = s.Exit(1)
		return waitErr
	}
	_ = s.Exit(0)
	return nil
}

func runDirect(s ssh.Session, cmd *exec.Cmd) error {
	slog.Info("starting direct command", "path", cmd.Path, "args", cmd.Args)
	cmd.Stdin = s
	cmd.Stdout = s
	cmd.Stderr = s.Stderr()
	if err := cmd.Start(); err != nil {
		slog.Error("start direct command failed", "err", err)
		_, _ = fmt.Fprintf(s.Stderr(), "start: %v\n", err)
		_ = s.Exit(1)
		return err
	}
	slog.Info("direct command started", "pid", cmd.Process.Pid)
	if err := cmd.Wait(); err != nil {
		slog.Info("direct command exited", "err", err)
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			_ = s.Exit(exitErr.ExitCode())
			return nil
		}
		_ = s.Exit(1)
		return err
	}
	_ = s.Exit(0)
	return nil
}

func terminalModesString(modes gossh.TerminalModes) string {
	if len(modes) == 0 {
		return ""
	}
	keys := make([]int, 0, len(modes))
	for op := range modes {
		keys = append(keys, int(op))
	}
	sort.Ints(keys)
	parts := make([]string, 0, len(keys))
	for _, op := range keys {
		parts = append(parts, fmt.Sprintf("%d=%d", op, modes[uint8(op)]))
	}
	return strings.Join(parts, ",")
}

func isExpectedExit(err error) bool {
	if err == nil {
		return true
	}
	var exitErr *exec.ExitError
	return errors.As(err, &exitErr)
}

func fatalf(format string, args ...any) {
	slog.Error("fatal", "msg", fmt.Sprintf(format, args...))
	os.Exit(1)
}
