package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/signal"

	"github.com/alecthomas/kong"
)

type cli struct {
	Command     string `short:"c" help:"Run a command string."`
	Interactive bool   `short:"i" help:"Read commands interactively after any -c command."`
}

func main() {
	var cli cli
	ctx := kong.Parse(&cli,
		kong.Name("hello-world-shell"),
		kong.Description("A tiny hello-world shell."),
		kong.UsageOnError(),
	)
	if cli.Command == "" && !cli.Interactive {
		ctx.FatalIfErrorf(fmt.Errorf("one of -c or -i is required"))
	}

	sh := newShell(newWriteFS(newEmbedFS()), os.Stdin, os.Stdout, os.Stderr)

	if cli.Command != "" {
		if err := sh.run(cli.Command); err != nil {
			fatalf("%v", err)
		}
	}

	if cli.Interactive {
		if err := runInteractive(sh, os.Stdin); err != nil {
			fatalf("%v", err)
		}
		return
	}
}

func runInteractive(sh *shell, r io.Reader) error {
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, os.Interrupt)
	defer signal.Stop(interrupts)

	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case <-interrupts:
				_, _ = fmt.Fprintln(sh.out)
				printPrompt(sh)
			case <-done:
				return
			}
		}
	}()

	scanner := bufio.NewScanner(r)
	printPrompt(sh)
	for scanner.Scan() {
		if err := sh.run(scanner.Text()); err != nil {
			_, _ = fmt.Fprintln(sh.err, err)
		}
		printPrompt(sh)
	}
	_, _ = fmt.Fprintln(sh.out)
	return scanner.Err()
}

func printPrompt(sh *shell) {
	_, _ = fmt.Fprintf(sh.out, "%s $ ", sh.cwd)
}

func fatalf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
