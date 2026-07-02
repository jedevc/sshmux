package main

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"
)

//go:embed root
var embeddedFiles embed.FS

const maxFilesystemBytes = 64 << 10

type writableFS interface {
	WriteFile(name string, data []byte, append bool) error
}

type removableFS interface {
	Remove(name string) error
}

type touchFS interface {
	Touch(name string) error
}

type dirFS interface {
	Mkdir(name string) error
	Rmdir(name string) error
}

type renameFS interface {
	Rename(oldName, newName string) error
}

func newEmbedFS() fs.FS {
	fsys, err := fs.Sub(embeddedFiles, "root")
	if err != nil {
		panic(err)
	}
	return fsys
}

type writeFS struct {
	base    fs.FS
	files   map[string][]byte
	dirs    map[string]bool
	deleted map[string]bool
}

func newWriteFS(base fs.FS) *writeFS {
	return &writeFS{base: base, files: map[string][]byte{}, dirs: map[string]bool{}, deleted: map[string]bool{}}
}

func (w *writeFS) Open(name string) (fs.File, error) {
	name = fsName(name)
	if w.deleted[name] {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	if w.dirs[name] {
		entries, err := w.ReadDir(name)
		if err != nil {
			return nil, err
		}
		return &writeDir{name: path.Base(name), entries: entries}, nil
	}
	if data, ok := w.files[name]; ok {
		return &writeFile{name: path.Base(name), r: bytes.NewReader(data)}, nil
	}
	return w.base.Open(name)
}

func (w *writeFS) ReadDir(name string) ([]fs.DirEntry, error) {
	name = fsName(name)
	entries, err := fs.ReadDir(w.base, name)
	if err != nil && !w.dirs[name] {
		return nil, err
	}

	seen := map[string]fs.DirEntry{}
	for _, entry := range entries {
		if w.deleted[path.Join(name, entry.Name())] {
			continue
		}
		seen[entry.Name()] = entry
	}
	for file := range w.files {
		if path.Dir(file) == name && !w.deleted[file] {
			seen[path.Base(file)] = writeDirEntry{name: path.Base(file), size: int64(len(w.files[file]))}
		}
	}
	for dir := range w.dirs {
		if dir != name && path.Dir(dir) == name && !w.deleted[dir] {
			seen[path.Base(dir)] = writeDirEntry{name: path.Base(dir), dir: true}
		}
	}

	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)

	entries = entries[:0]
	for _, name := range names {
		entries = append(entries, seen[name])
	}
	return entries, nil
}

func (w *writeFS) WriteFile(name string, data []byte, appendData bool) error {
	name = fsName(name)
	if w.deleted[path.Dir(name)] {
		return fmt.Errorf("%s: no such directory", displayPath(path.Dir(name)))
	}
	if info, err := fs.Stat(w, name); err == nil && info.IsDir() {
		return fmt.Errorf("%s: is a directory", displayPath(name))
	}
	if dir := path.Dir(name); dir != "." {
		info, err := fs.Stat(w, dir)
		if err != nil || !info.IsDir() {
			return fmt.Errorf("%s: no such directory", displayPath(dir))
		}
	}
	if appendData {
		current := append([]byte(nil), w.files[name]...)
		if current == nil && !w.deleted[name] {
			base, err := fs.ReadFile(w.base, name)
			if err == nil {
				current = append([]byte(nil), base...)
			}
		}
		data = append(current, data...)
	}
	if err := w.checkSpace(name, data); err != nil {
		return err
	}
	w.deleted[name] = false
	w.files[name] = append([]byte(nil), data...)
	return nil
}

func (w *writeFS) Remove(name string) error {
	name = fsName(name)
	info, err := fs.Stat(w, name)
	if err != nil {
		return fmt.Errorf("%s: no such file", displayPath(name))
	}
	if info.IsDir() {
		return fmt.Errorf("%s: is a directory", displayPath(name))
	}
	delete(w.files, name)
	w.deleted[name] = true
	return nil
}

func (w *writeFS) Mkdir(name string) error {
	name = fsName(name)
	if name == "." {
		return fmt.Errorf("%s: file exists", displayPath(name))
	}
	if _, err := fs.Stat(w, name); err == nil {
		return fmt.Errorf("%s: file exists", displayPath(name))
	}
	parent := path.Dir(name)
	info, err := fs.Stat(w, parent)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("%s: no such directory", displayPath(parent))
	}
	w.deleted[name] = false
	w.dirs[name] = true
	return nil
}

func (w *writeFS) Rmdir(name string) error {
	name = fsName(name)
	if name == "." {
		return fmt.Errorf("%s: cannot remove root", displayPath(name))
	}
	info, err := fs.Stat(w, name)
	if err != nil {
		return fmt.Errorf("%s: no such directory", displayPath(name))
	}
	if !info.IsDir() {
		return fmt.Errorf("%s: not a directory", displayPath(name))
	}
	entries, err := w.ReadDir(name)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return fmt.Errorf("%s: directory not empty", displayPath(name))
	}
	delete(w.dirs, name)
	w.deleted[name] = true
	return nil
}

func (w *writeFS) Rename(oldName, newName string) error {
	oldName = fsName(oldName)
	newName = fsName(newName)
	if info, err := fs.Stat(w, newName); err == nil && info.IsDir() {
		newName = path.Join(newName, path.Base(oldName))
	}
	data, err := fs.ReadFile(w, oldName)
	if err != nil {
		return fmt.Errorf("%s: no such file", displayPath(oldName))
	}
	if err := w.WriteFile(newName, data, false); err != nil {
		return err
	}
	delete(w.files, oldName)
	w.deleted[oldName] = true
	return nil
}

func (w *writeFS) Touch(name string) error {
	name = fsName(name)
	info, err := fs.Stat(w, name)
	if err == nil && info.IsDir() {
		return fmt.Errorf("%s: is a directory", displayPath(name))
	}
	if err == nil {
		return nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return w.WriteFile(name, nil, false)
}

func (w *writeFS) checkSpace(name string, data []byte) error {
	used := 0
	for file, content := range w.files {
		if file != name {
			used += len(content)
		}
	}
	if used+len(data) > maxFilesystemBytes {
		return fmt.Errorf("filesystem is full: %d byte limit exceeded", maxFilesystemBytes)
	}
	return nil
}

type writeFile struct {
	name string
	r    *bytes.Reader
}

func (f *writeFile) Stat() (fs.FileInfo, error) {
	return writeFileInfo{name: f.name, size: f.r.Size()}, nil
}
func (f *writeFile) Read(p []byte) (int, error) { return f.r.Read(p) }
func (f *writeFile) Close() error               { return nil }

type writeDirEntry struct {
	name string
	size int64
	dir  bool
}

func (e writeDirEntry) Name() string { return e.name }
func (e writeDirEntry) IsDir() bool  { return e.dir }
func (e writeDirEntry) Type() fs.FileMode {
	if e.dir {
		return fs.ModeDir
	}
	return 0
}
func (e writeDirEntry) Info() (fs.FileInfo, error) {
	return writeFileInfo{name: e.name, size: e.size, dir: e.dir}, nil
}

type writeFileInfo struct {
	name string
	size int64
	dir  bool
}

func (i writeFileInfo) Name() string { return i.name }
func (i writeFileInfo) Size() int64  { return i.size }
func (i writeFileInfo) Mode() fs.FileMode {
	if i.dir {
		return fs.ModeDir | 0755
	}
	return 0644
}
func (i writeFileInfo) ModTime() time.Time { return time.Time{} }
func (i writeFileInfo) IsDir() bool        { return i.dir }
func (i writeFileInfo) Sys() any           { return nil }

type writeDir struct {
	name    string
	offset  int
	entries []fs.DirEntry
}

func (d *writeDir) Stat() (fs.FileInfo, error) { return writeFileInfo{name: d.name, dir: true}, nil }
func (d *writeDir) Read([]byte) (int, error)   { return 0, io.EOF }
func (d *writeDir) Close() error               { return nil }
func (d *writeDir) ReadDir(n int) ([]fs.DirEntry, error) {
	if d.offset >= len(d.entries) && n > 0 {
		return nil, io.EOF
	}
	if n <= 0 || d.offset+n > len(d.entries) {
		n = len(d.entries) - d.offset
	}
	entries := d.entries[d.offset : d.offset+n]
	d.offset += n
	return entries, nil
}

func fsName(name string) string {
	name = strings.TrimPrefix(path.Clean("/"+name), "/")
	if name == "" {
		return "."
	}
	return name
}

func displayPath(name string) string {
	if name == "." {
		return "/"
	}
	return "/" + name
}

var _ fs.FS = (*writeFS)(nil)
var _ fs.ReadDirFS = (*writeFS)(nil)
var _ writableFS = (*writeFS)(nil)
var _ removableFS = (*writeFS)(nil)
var _ touchFS = (*writeFS)(nil)
var _ dirFS = (*writeFS)(nil)
var _ renameFS = (*writeFS)(nil)
