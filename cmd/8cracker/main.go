package main

import (
	"flag"
	"fmt"
	"os"

	"8cracker/internal/core"
	"8cracker/internal/tui"
)

func main() {
	kill := flag.Bool("kill", false, "Kill processes that conflict with monitor mode (airmon-ng check kill)")
	runCPU := flag.Bool("run-cpu", false, "Crack on CPU with John the Ripper instead of GPU (hashcat)")
	show := flag.Bool("show", false, "Show already-cracked passwords and exit (no TUI)")
	flag.Parse()

	// --show prints recovered passwords and exits without launching the TUI.
	if *show {
		fmt.Print(core.ShowResults())
		return
	}

	if err := tui.Run(*kill, *runCPU); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
