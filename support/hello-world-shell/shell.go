package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

type shell struct {
	fs  fs.FS
	cwd string
	env map[string]string
	in  io.Reader
	out io.Writer
	err io.Writer
}

func newShell(fsys fs.FS, in io.Reader, out, err io.Writer) *shell {
	return &shell{
		fs:  fsys,
		cwd: "/home/guest",
		env: map[string]string{
			"HOME": "/home/guest",
			"PWD":  "/home/guest",
		},
		in:  in,
		out: out,
		err: err,
	}
}

func (s *shell) run(src string) error {
	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(src), "stdin")
	if err != nil {
		return err
	}
	return s.runFile(file)
}

func (s *shell) runFile(file *syntax.File) error {
	for _, stmt := range file.Stmts {
		if err := s.runStmt(stmt); err != nil {
			return err
		}
	}
	return nil
}

func (s *shell) runStmt(stmt *syntax.Stmt) error {
	if stmt.Negated || stmt.Background || stmt.Coprocess {
		return errors.New("operators, background jobs, and coprocesses are not supported")
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok {
		return fmt.Errorf("unsupported command %T", stmt.Cmd)
	}

	local := map[string]string{}
	for _, assign := range call.Assigns {
		value := ""
		if assign.Value != nil {
			var err error
			value, err = s.word(assign.Value, local)
			if err != nil {
				return err
			}
		}
		local[assign.Name.Value] = value
	}
	if len(call.Args) == 0 {
		for key, value := range local {
			s.env[key] = value
		}
		return nil
	}

	args := make([]string, 0, len(call.Args))
	for _, word := range call.Args {
		arg, err := s.word(word, local)
		if err != nil {
			return err
		}
		args = append(args, arg)
	}

	out := s.out
	in := s.in
	for _, redir := range stmt.Redirs {
		target, err := s.word(redir.Word, local)
		if err != nil {
			return err
		}
		switch redir.Op {
		case syntax.RdrOut, syntax.ClbOut:
			buf := &bytes.Buffer{}
			out = writeback{Writer: buf, fn: func() error { return s.writeFile(target, buf.Bytes(), false) }}
		case syntax.AppOut:
			buf := &bytes.Buffer{}
			out = writeback{Writer: buf, fn: func() error { return s.writeFile(target, buf.Bytes(), true) }}
		case syntax.RdrIn:
			data, err := s.readFile(target)
			if err != nil {
				return err
			}
			in = strings.NewReader(data)
		default:
			return fmt.Errorf("unsupported redirect %s", redir.Op)
		}
	}

	if err := s.runArgs(args, in, out); err != nil {
		return err
	}
	if wb, ok := out.(writeback); ok {
		return wb.fn()
	}
	return nil
}

type writeback struct {
	io.Writer
	fn func() error
}

func (s *shell) word(word *syntax.Word, local map[string]string) (string, error) {
	var b strings.Builder
	for _, part := range word.Parts {
		value, err := s.wordPart(part, local)
		if err != nil {
			return "", err
		}
		b.WriteString(value)
	}
	return b.String(), nil
}

func (s *shell) wordPart(part syntax.WordPart, local map[string]string) (string, error) {
	switch p := part.(type) {
	case *syntax.Lit:
		return p.Value, nil
	case *syntax.SglQuoted:
		return p.Value, nil
	case *syntax.DblQuoted:
		var b strings.Builder
		for _, inner := range p.Parts {
			value, err := s.wordPart(inner, local)
			if err != nil {
				return "", err
			}
			b.WriteString(value)
		}
		return b.String(), nil
	case *syntax.ParamExp:
		if p.Param == nil {
			return "", errors.New("unsupported parameter expansion")
		}
		if value, ok := local[p.Param.Value]; ok {
			return value, nil
		}
		return s.env[p.Param.Value], nil
	case *syntax.CmdSubst:
		return s.commandSubstitution(p)
	default:
		return "", fmt.Errorf("unsupported expansion or quoting %T", part)
	}
}

func (s *shell) commandSubstitution(sub *syntax.CmdSubst) (string, error) {
	var out bytes.Buffer
	child := *s
	child.out = &out
	if err := child.runFile(&syntax.File{Stmts: sub.Stmts}); err != nil {
		return "", err
	}
	return strings.TrimRight(out.String(), "\n"), nil
}

func (s *shell) clean(name string) string {
	if path.IsAbs(name) {
		return path.Clean(name)
	}
	return path.Clean(path.Join(s.cwd, name))
}

func (s *shell) readFile(name string) (string, error) {
	clean := s.clean(name)
	data, err := fs.ReadFile(s.fs, fsName(clean))
	if err != nil {
		if info, statErr := fs.Stat(s.fs, fsName(clean)); statErr == nil && info.IsDir() {
			return "", fmt.Errorf("cat: %s: is a directory", clean)
		}
		return "", fmt.Errorf("cat: %s: no such file", clean)
	}
	return string(data), nil
}

func (s *shell) writeFile(name string, data []byte, appendData bool) error {
	wfs, ok := s.fs.(writableFS)
	if !ok {
		return errors.New("filesystem is read-only")
	}
	return wfs.WriteFile(s.clean(name), data, appendData)
}
