// Command migrate runs control-plane database migrations.
package main

import (
	"fmt"
	"os"

	"github.com/aegis/control-plane/internal/store"
)

func main() {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		fmt.Fprintln(os.Stderr, "DATABASE_URL is required")
		os.Exit(1)
	}
	if err := store.Migrate(dbURL); err != nil {
		fmt.Fprintln(os.Stderr, "migrate failed:", err)
		os.Exit(1)
	}
	fmt.Println("migrations applied")
}
