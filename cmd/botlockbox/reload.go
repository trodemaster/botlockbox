package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func runReload(args []string) {
	fs := flag.NewFlagSet("reload", flag.ExitOnError)
	pidfilePath := fs.String("pidfile", "", "path to the PID file written by 'botlockbox serve' (required)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: botlockbox reload [flags]")
		fmt.Fprintln(os.Stderr, "Sends SIGHUP to a running botlockbox serve process to trigger a live secret reload.")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if *pidfilePath == "" {
		fmt.Fprintln(os.Stderr, "error: --pidfile is required")
		fs.Usage()
		os.Exit(1)
	}

	data, err := os.ReadFile(*pidfilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading PID file %q: %v\n", *pidfilePath, err)
		os.Exit(1)
	}

	pidStr := strings.TrimSpace(string(data))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid PID in file %q: %q\n", *pidfilePath, pidStr)
		os.Exit(1)
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error finding process %d: %v\n", pid, err)
		os.Exit(1)
	}

	if err := proc.Signal(syscall.SIGHUP); err != nil {
		fmt.Fprintf(os.Stderr, "error sending SIGHUP to PID %d: %v\n", pid, err)
		os.Exit(1)
	}

	fmt.Printf("SIGHUP sent to PID %d\n", pid)
}
