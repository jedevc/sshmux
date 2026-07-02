package main

import (
	"bytes"
	"strings"
	"testing"

	"gotest.tools/v3/golden"
)

func TestShellGolden(t *testing.T) {
	var out bytes.Buffer
	sh := newShell(newWriteFS(newEmbedFS()), bytes.NewReader([]byte("stdin line\n")), &out, &out)

	script := `pwd
ls /
ls
cat /README.txt
cat /etc/hostname
cat notes.txt
whoami
touch scratch.txt
ls
rm scratch.txt
ls
mkdir tmp
touch tmp/a.txt
cp notes.txt tmp/notes.copy
mv tmp/a.txt tmp/b.txt
ls tmp
grep router notes.txt
rm tmp/b.txt
rm tmp/notes.copy
rmdir tmp
name=world
echo hello $name
echo "cwd=$(pwd)"
cd docs
pwd
cat intro.md
echo redirected > /home/guest/out.txt
echo appended >> /home/guest/out.txt
cat /home/guest/out.txt
cat < /home/guest/out.txt
cat
`

	if err := sh.run(script); err != nil {
		t.Fatal(err)
	}

	golden.Assert(t, out.String(), "shell.golden")
}

func TestInteractivePromptGolden(t *testing.T) {
	var out bytes.Buffer
	sh := newShell(newWriteFS(newEmbedFS()), bytes.NewReader(nil), &out, &out)

	if err := runInteractive(sh, bytes.NewReader([]byte("pwd\ncd /etc\npwd\n"))); err != nil {
		t.Fatal(err)
	}

	golden.Assert(t, out.String(), "prompt.golden")
}

func TestFilesystemSpaceLimit(t *testing.T) {
	fsys := newWriteFS(newEmbedFS())
	err := fsys.WriteFile("home/guest/big.txt", []byte(strings.Repeat("x", maxFilesystemBytes+1)), false)
	if err == nil {
		t.Fatal("expected filesystem space error")
	}
	if !strings.Contains(err.Error(), "filesystem is full") {
		t.Fatalf("expected filesystem full error, got %v", err)
	}
}

func TestFilesystemSpaceLimitAcrossFiles(t *testing.T) {
	fsys := newWriteFS(newEmbedFS())
	if err := fsys.WriteFile("home/guest/a.txt", []byte(strings.Repeat("a", maxFilesystemBytes/2)), false); err != nil {
		t.Fatal(err)
	}
	err := fsys.WriteFile("home/guest/b.txt", []byte(strings.Repeat("b", maxFilesystemBytes/2+1)), false)
	if err == nil {
		t.Fatal("expected cumulative filesystem space error")
	}
	if !strings.Contains(err.Error(), "filesystem is full") {
		t.Fatalf("expected filesystem full error, got %v", err)
	}
}

func TestWriteFSDirectories(t *testing.T) {
	fsys := newWriteFS(newEmbedFS())
	if err := fsys.Mkdir("home/guest/tmp"); err != nil {
		t.Fatal(err)
	}
	if err := fsys.WriteFile("home/guest/tmp/file.txt", []byte("hello"), false); err != nil {
		t.Fatal(err)
	}
	if err := fsys.Rmdir("home/guest/tmp"); err == nil {
		t.Fatal("expected non-empty directory error")
	}
	if err := fsys.Remove("home/guest/tmp/file.txt"); err != nil {
		t.Fatal(err)
	}
	if err := fsys.Rmdir("home/guest/tmp"); err != nil {
		t.Fatal(err)
	}
}
