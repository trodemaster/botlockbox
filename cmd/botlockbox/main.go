package main

import (
	"fmt"
	"os"
)

const usage = `botlockbox — credential-injecting HTTPS/HTTP MITM proxy

Usage:
  botlockbox seal   [flags]   seal secrets into an age-encrypted envelope
  botlockbox serve  [flags]   run the proxy server
  botlockbox reload [flags]   send SIGHUP to a running serve process to reload secrets

Run 'botlockbox <subcommand> -h' for subcommand flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	switch os.Args[1] {
	case "seal":
		runSeal(os.Args[2:])
	case "serve":
		runServe(os.Args[2:])
	case "reload":
		runReload(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", os.Args[1])
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}
}
