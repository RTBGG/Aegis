package agent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
)

// writeDynamic atomically writes the customer site blocks Caddy imports.
func (c Config) writeDynamic(content string) error {
	if err := os.MkdirAll(c.SitesDir, 0o755); err != nil {
		return err
	}
	tmp := c.dynamicFile() + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, c.dynamicFile())
}

// startCaddy launches the managed Caddy process.
func (c Config) startCaddy(ctx context.Context) (*exec.Cmd, error) {
	cmd := exec.CommandContext(ctx, c.CaddyBin, "run", "--config", c.Caddyfile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

// reloadCaddy applies the current Caddyfile via the admin API.
func (c Config) reloadCaddy() error {
	cmd := exec.Command(c.CaddyBin, "reload", "--config", c.Caddyfile, "--address", c.CaddyAdmin)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("caddy reload: %w: %s", err, out)
	}
	return nil
}
