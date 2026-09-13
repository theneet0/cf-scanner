package main

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"sync"

	"github.com/fatih/color"
)

var (
	exitOnce sync.Once
	exitFunc = os.Exit
)

// resetExitOnceForTest resets exitOnce for testing purposes.
func resetExitOnceForTest() {
	exitOnce = sync.Once{}
}

// exitOnError prints the cause of the error in the console and, on Windows,
// prevents the program from closing on the spot by waiting for user input before exiting.
func exitOnError(err any) {
	if err == nil {
		return
	}
	exitOnce.Do(func() {
		fmt.Println()
		color.Red("Error: %v\n", err)
		waitOnWindows()
		exitFunc(1)
	})
}

// waitOnWindows prompts the user to press Enter before exiting on Windows,
// ensuring that console windows spawned by GUI/Explorer or shortcuts do not close immediately.
func waitOnWindows() {
	if runtime.GOOS == "windows" {
		fmt.Print("\nPress Enter to exit...")
		reader := bufio.NewReader(os.Stdin)
		_, _ = reader.ReadBytes('\n')
	}
}
