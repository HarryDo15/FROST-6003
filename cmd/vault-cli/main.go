// Command vault-cli will be the member-facing client for the group vault.
// It is a placeholder in Week 1.
package main

import (
	"fmt"
	"os"
)

func main() {
	if _, err := fmt.Fprintln(os.Stderr, "vault-cli: not implemented yet"); err != nil {
		os.Exit(2)
	}
	os.Exit(1)
}
