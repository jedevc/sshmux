package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

const (
	maxScriptBytes = 8 << 10
	maxNodes       = 512
	maxArgs        = 32
	maxOutputBytes = 64 << 10
)

func main() {
	fs := newMemoryFS()
	sh := &shell{
		fs:  fs,
		cwd: "/home/guest",
		out: &limitWriter{w: os.Stdout, remaining: maxOutputBytes},
		err: &limitWriter{w: os.Stderr, remaining: maxOutputBytes},
	}

	input, err := io.ReadAll(io.LimitReader(os.Stdin, maxScriptBytes+1))
	if err != nil {
		fatalf("read stdin: %v", err)
	}
	if len(input) > maxScriptBytes {
		fatalf("script is too large")
	}
	if len(bytes.TrimSpace(input)) == 0 {
		input = []byte("pwd\nls\ncat /README.txt\necho hello from mvdan/sh syntax\n")
	}

	if err := sh.run(string(input)); err != nil {
		fatalf("%v", err)
	}
}

type shell struct {
	fs  *memoryFS
	cwd string
	out io.Writer
	err io.Writer
}

func (s *shell) run(src string) error {
	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(src), "stdin")
	if err != nil {
		return err
	}
	if err := validate(file); err != nil {
		return err
	}
	for _, stmt := range file.Stmts {
		if err := s.runStmt(stmt); err != nil {
			return err
		}
	}
	return nil
}

func validate(file *syntax.File) error {
	nodes := 0
	var err error
	syntax.Walk(file, func(node syntax.Node) bool {
		if err != nil || node == nil {
			return false
		}
		nodes++
		if nodes > maxNodes {
			err = errors.New("script is too complex")
			return false
		}

		switch n := node.(type) {
		case *syntax.File, *syntax.Stmt, *syntax.CallExpr, *syntax.Word, *syntax.Lit, *syntax.SglQuoted, *syntax.DblQuoted:
			return true
		case *syntax.Comment:
			return true
		case *syntax.Subshell, *syntax.Block, *syntax.BinaryCmd, *syntax.IfClause, *syntax.WhileClause, *syntax.ForClause, *syntax.CaseClause, *syntax.FuncDecl, *syntax.ArithmCmd, *syntax.TestClause, *syntax.DeclClause, *syntax.LetClause, *syntax.TimeClause, *syntax.CoprocClause:
			err = fmt.Errorf("unsupported shell construct %T", n)
			return false
		default:
			err = fmt.Errorf("unsupported shell syntax %T", n)
			return false
		}
	})
	return err
}

func (s *shell) runStmt(stmt *syntax.Stmt) error {
	if stmt.Negated || stmt.Background || stmt.Coprocess || len(stmt.Redirs) > 0 {
		return errors.New("operators, background jobs, coprocesses, and redirects are not supported")
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok {
		return fmt.Errorf("unsupported command %T", stmt.Cmd)
	}
	if len(call.Assigns) > 0 {
		return errors.New("assignments are not supported")
	}
	if len(call.Args) == 0 {
		return nil
	}
	if len(call.Args) > maxArgs {
		return errors.New("too many arguments")
	}

	args := make([]string, 0, len(call.Args))
	for _, word := range call.Args {
		arg, err := literalWord(word)
		if err != nil {
			return err
		}
		args = append(args, arg)
	}

	switch args[0] {
	case "pwd":
		return s.pwd(args[1:])
	case "ls":
		return s.ls(args[1:])
	case "cat":
		return s.cat(args[1:])
	case "echo":
		return s.echo(args[1:])
	case "cd":
		return s.cd(args[1:])
	case "help":
		return s.help(args[1:])
	case "exit":
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func literalWord(word *syntax.Word) (string, error) {
	var b strings.Builder
	for _, part := range word.Parts {
		value, err := literalPart(part)
		if err != nil {
			return "", err
		}
		b.WriteString(value)
	}
	return b.String(), nil
}

func literalPart(part syntax.WordPart) (string, error) {
	switch p := part.(type) {
	case *syntax.Lit:
		return p.Value, nil
	case *syntax.SglQuoted:
		if p.Dollar {
			return "", errors.New("dollar single quotes are not supported")
		}
		return p.Value, nil
	case *syntax.DblQuoted:
		if p.Dollar {
			return "", errors.New("localized double quotes are not supported")
		}
		var b strings.Builder
		for _, inner := range p.Parts {
			value, err := literalPart(inner)
			if err != nil {
				return "", err
			}
			b.WriteString(value)
		}
		return b.String(), nil
	default:
		return "", fmt.Errorf("unsupported expansion or quoting %T", part)
	}
}

func (s *shell) pwd(args []string) error {
	if len(args) != 0 {
		return errors.New("pwd takes no arguments")
	}
	_, err := fmt.Fprintln(s.out, s.cwd)
	return err
}

func (s *shell) ls(args []string) error {
	if len(args) > 1 {
		return errors.New("ls takes at most one path")
	}
	target := s.cwd
	if len(args) == 1 {
		target = s.clean(args[0])
	}
	entries, err := s.fs.list(target)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if _, err := fmt.Fprintln(s.out, entry); err != nil {
			return err
		}
	}
	return nil
}

func (s *shell) cat(args []string) error {
	if len(args) == 0 {
		return errors.New("cat requires at least one path")
	}
	for _, arg := range args {
		content, err := s.fs.read(s.clean(arg))
		if err != nil {
			return err
		}
		if _, err := fmt.Fprint(s.out, content); err != nil {
			return err
		}
		if !strings.HasSuffix(content, "\n") {
			if _, err := fmt.Fprintln(s.out); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *shell) echo(args []string) error {
	_, err := fmt.Fprintln(s.out, strings.Join(args, " "))
	return err
}

func (s *shell) cd(args []string) error {
	if len(args) > 1 {
		return errors.New("cd takes at most one path")
	}
	target := "/home/guest"
	if len(args) == 1 {
		target = s.clean(args[0])
	}
	if !s.fs.isDir(target) {
		return fmt.Errorf("cd: %s: not a directory", target)
	}
	s.cwd = target
	return nil
}

func (s *shell) help(args []string) error {
	if len(args) != 0 {
		return errors.New("help takes no arguments")
	}
	_, err := fmt.Fprintln(s.out, "builtins: cat cd echo exit help ls pwd")
	return err
}

func (s *shell) clean(name string) string {
	if path.IsAbs(name) {
		return path.Clean(name)
	}
	return path.Clean(path.Join(s.cwd, name))
}

type memoryFS struct {
	files map[string]string
	dirs  map[string]bool
}

func newMemoryFS() *memoryFS {
	fs := &memoryFS{
		files: map[string]string{
			"/README.txt":               "Welcome to the in-memory shell. Try: ls /home/guest/docs\n",
			"/home/guest/notes.txt":     "This file exists only in memory.\n",
			"/home/guest/docs/intro.md": "# Intro\nNo host filesystem access is available here.\n",
		},
		dirs: map[string]bool{
			"/":                true,
			"/home":            true,
			"/home/guest":      true,
			"/home/guest/docs": true,
		},
	}
	return fs
}

func (fs *memoryFS) read(name string) (string, error) {
	content, ok := fs.files[name]
	if !ok {
		if fs.dirs[name] {
			return "", fmt.Errorf("cat: %s: is a directory", name)
		}
		return "", fmt.Errorf("cat: %s: no such file", name)
	}
	return content, nil
}

func (fs *memoryFS) list(name string) ([]string, error) {
	if content, ok := fs.files[name]; ok {
		_ = content
		return []string{path.Base(name)}, nil
	}
	if !fs.dirs[name] {
		return nil, fmt.Errorf("ls: %s: no such directory", name)
	}

	seen := map[string]bool{}
	for dir := range fs.dirs {
		if dir == name || path.Dir(dir) != name {
			continue
		}
		seen[path.Base(dir)+"/"] = true
	}
	for file := range fs.files {
		if path.Dir(file) == name {
			seen[path.Base(file)] = true
		}
	}

	entries := make([]string, 0, len(seen))
	for entry := range seen {
		entries = append(entries, entry)
	}
	sort.Strings(entries)
	return entries, nil
}

func (fs *memoryFS) isDir(name string) bool {
	return fs.dirs[name]
}

type limitWriter struct {
	w         io.Writer
	remaining int
}

func (w *limitWriter) Write(p []byte) (int, error) {
	truncated := false
	if len(p) > w.remaining {
		p = p[:w.remaining]
		truncated = true
	}
	if len(p) == 0 {
		return 0, errors.New("output limit exceeded")
	}
	n, err := w.w.Write(p)
	w.remaining -= n
	if err == nil && truncated {
		err = errors.New("output limit exceeded")
	}
	return n, err
}

func fatalf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
