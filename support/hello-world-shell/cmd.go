package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
)

func (s *shell) runArgs(args []string, in io.Reader, out io.Writer) error {
	switch args[0] {
	case "cat":
		return s.cat(args[1:], in, out)
	case "cd":
		return s.cd(args[1:])
	case "clear":
		return s.clear(args[1:], out)
	case "cp":
		return s.cp(args[1:])
	case "echo":
		return s.echo(args[1:], out)
	case "exit":
		return nil
	case "grep":
		return s.grep(args[1:], in, out)
	case "help":
		return s.help(args[1:], out)
	case "ls":
		return s.ls(args[1:], out)
	case "mkdir":
		return s.mkdir(args[1:])
	case "mv":
		return s.mv(args[1:])
	case "pwd":
		return s.pwd(args[1:], out)
	case "rm":
		return s.rm(args[1:])
	case "rmdir":
		return s.rmdir(args[1:])
	case "touch":
		return s.touch(args[1:])
	case "whoami":
		return s.whoami(args[1:], out)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func (s *shell) pwd(args []string, out io.Writer) error {
	if len(args) != 0 {
		return errors.New("pwd takes no arguments")
	}
	_, err := fmt.Fprintln(out, s.cwd)
	return err
}

func (s *shell) ls(args []string, out io.Writer) error {
	if len(args) > 1 {
		return errors.New("ls takes at most one path")
	}
	target := s.cwd
	if len(args) == 1 {
		target = s.clean(args[0])
	}
	entries, err := fs.ReadDir(s.fs, fsName(target))
	if err != nil {
		if errors.Is(err, fs.ErrInvalid) || errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("ls: %s: no such directory", target)
		}
		data, readErr := fs.ReadFile(s.fs, fsName(target))
		if readErr == nil {
			_ = data
			_, err = fmt.Fprintln(out, path.Base(target))
			return err
		}
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			name += "/"
		}
		if _, err := fmt.Fprintln(out, name); err != nil {
			return err
		}
	}
	return nil
}

func (s *shell) cat(args []string, in io.Reader, out io.Writer) error {
	if len(args) == 0 {
		_, err := io.Copy(out, in)
		return err
	}
	for _, arg := range args {
		content, err := s.readFile(arg)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprint(out, content); err != nil {
			return err
		}
		if !strings.HasSuffix(content, "\n") {
			if _, err := fmt.Fprintln(out); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *shell) echo(args []string, out io.Writer) error {
	_, err := fmt.Fprintln(out, strings.Join(args, " "))
	return err
}

func (s *shell) whoami(args []string, out io.Writer) error {
	if len(args) != 0 {
		return errors.New("whoami takes no arguments")
	}
	_, err := fmt.Fprintln(out, "guest")
	return err
}

func (s *shell) clear(args []string, out io.Writer) error {
	if len(args) != 0 {
		return errors.New("clear takes no arguments")
	}
	_, err := fmt.Fprint(out, "\033[H\033[2J")
	return err
}

func (s *shell) grep(args []string, in io.Reader, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("grep requires a pattern")
	}
	pattern := args[0]
	if len(args) == 1 {
		return grepReader(pattern, in, out)
	}
	for _, arg := range args[1:] {
		content, err := s.readFile(arg)
		if err != nil {
			return err
		}
		if err := grepReader(pattern, strings.NewReader(content), out); err != nil {
			return err
		}
	}
	return nil
}

func grepReader(pattern string, r io.Reader, out io.Writer) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, pattern) {
			if _, err := fmt.Fprintln(out, line); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *shell) mkdir(args []string) error {
	if len(args) == 0 {
		return errors.New("mkdir requires at least one path")
	}
	fsys, ok := s.fs.(dirFS)
	if !ok {
		return errors.New("filesystem is read-only")
	}
	for _, arg := range args {
		if err := fsys.Mkdir(s.clean(arg)); err != nil {
			return fmt.Errorf("mkdir: %w", err)
		}
	}
	return nil
}

func (s *shell) rmdir(args []string) error {
	if len(args) == 0 {
		return errors.New("rmdir requires at least one path")
	}
	fsys, ok := s.fs.(dirFS)
	if !ok {
		return errors.New("filesystem is read-only")
	}
	for _, arg := range args {
		if err := fsys.Rmdir(s.clean(arg)); err != nil {
			return fmt.Errorf("rmdir: %w", err)
		}
	}
	return nil
}

func (s *shell) cp(args []string) error {
	if len(args) != 2 {
		return errors.New("cp requires source and destination")
	}
	content, err := s.readFile(args[0])
	if err != nil {
		return fmt.Errorf("cp: %w", err)
	}
	dst := s.clean(args[1])
	if info, err := fs.Stat(s.fs, fsName(dst)); err == nil && info.IsDir() {
		dst = path.Join(dst, path.Base(s.clean(args[0])))
	}
	return s.writeFile(dst, []byte(content), false)
}

func (s *shell) mv(args []string) error {
	if len(args) != 2 {
		return errors.New("mv requires source and destination")
	}
	fsys, ok := s.fs.(renameFS)
	if !ok {
		return errors.New("filesystem is read-only")
	}
	if err := fsys.Rename(s.clean(args[0]), s.clean(args[1])); err != nil {
		return fmt.Errorf("mv: %w", err)
	}
	return nil
}

func (s *shell) touch(args []string) error {
	if len(args) == 0 {
		return errors.New("touch requires at least one path")
	}
	fsys, ok := s.fs.(touchFS)
	if !ok {
		return errors.New("filesystem is read-only")
	}
	for _, arg := range args {
		if err := fsys.Touch(s.clean(arg)); err != nil {
			return fmt.Errorf("touch: %w", err)
		}
	}
	return nil
}

func (s *shell) rm(args []string) error {
	if len(args) == 0 {
		return errors.New("rm requires at least one path")
	}
	fsys, ok := s.fs.(removableFS)
	if !ok {
		return errors.New("filesystem is read-only")
	}
	for _, arg := range args {
		if err := fsys.Remove(s.clean(arg)); err != nil {
			return fmt.Errorf("rm: %w", err)
		}
	}
	return nil
}

func (s *shell) cd(args []string) error {
	if len(args) > 1 {
		return errors.New("cd takes at most one path")
	}
	target := s.env["HOME"]
	if len(args) == 1 {
		target = s.clean(args[0])
	}
	info, err := fs.Stat(s.fs, fsName(target))
	if err != nil || !info.IsDir() {
		return fmt.Errorf("cd: %s: not a directory", target)
	}
	s.cwd = target
	s.env["PWD"] = target
	return nil
}

func (s *shell) help(args []string, out io.Writer) error {
	if len(args) != 0 {
		return errors.New("help takes no arguments")
	}
	_, err := fmt.Fprintln(out, "builtins: cat cd clear cp echo exit grep help ls mkdir mv pwd rm rmdir touch whoami")
	return err
}
