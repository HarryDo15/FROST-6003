// Command coordinator will orchestrate share distribution and recovery
// ceremonies between vault members. It is a placeholder in Week 1.
package main

import (
	"fmt"
	"os"
)

func main() {
	if _, err := fmt.Fprintln(os.Stderr, "coordinator: not implemented yet"); err != nil {
		os.Exit(2)
	}
	os.Exit(1)
}
