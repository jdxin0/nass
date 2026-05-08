// Package orchestrator runs `docker compose` commands for nass-managed apps.
package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

type Orchestrator struct {
	// ComposeRoot is the base directory for relative compose file paths.
	ComposeRoot string
	// DockerCompose is the executable, e.g. "docker compose" or "docker-compose".
	DockerCompose []string // split into argv tokens
}

// New parses the docker_compose config string ("docker compose" or "docker-compose")
// into argv form and returns an Orchestrator.
func New(composeRoot, dockerCompose string) *Orchestrator {
	if dockerCompose == "" {
		dockerCompose = "docker compose"
	}
	return &Orchestrator{
		ComposeRoot:   composeRoot,
		DockerCompose: strings.Fields(dockerCompose),
	}
}

// State is the lifecycle state reported back to the portal UI.
type State string

const (
	StateRunning State = "running"
	StateStopped State = "stopped"
	StateUnknown State = "unknown"
)

// Up runs `docker compose -f <file> up -d` for the named app.
func (o *Orchestrator) Up(ctx context.Context, composeFile string) (string, error) {
	path, err := o.resolve(composeFile)
	if err != nil {
		return "", err
	}
	return o.run(ctx, path, "up", "-d")
}

// Down runs `docker compose -f <file> down`.
func (o *Orchestrator) Down(ctx context.Context, composeFile string) (string, error) {
	path, err := o.resolve(composeFile)
	if err != nil {
		return "", err
	}
	return o.run(ctx, path, "down")
}

// DownWithVolumes runs `docker compose -f <file> down -v --remove-orphans`,
// removing named volumes and any orphaned containers. Used by uninstall.
func (o *Orchestrator) DownWithVolumes(ctx context.Context, composeFile string) (string, error) {
	path, err := o.resolve(composeFile)
	if err != nil {
		return "", err
	}
	return o.run(ctx, path, "down", "-v", "--remove-orphans")
}

// Restart runs `docker compose -f <file> restart`.
func (o *Orchestrator) Restart(ctx context.Context, composeFile string) (string, error) {
	path, err := o.resolve(composeFile)
	if err != nil {
		return "", err
	}
	return o.run(ctx, path, "restart")
}

// Kill sends SIGKILL to a service. Use this instead of Restart when graceful
// shutdown would let the app overwrite a config file we just edited
// (qBittorrent flushes its in-memory state to qBittorrent.conf on SIGTERM).
// An empty service kills every service in the compose project.
func (o *Orchestrator) Kill(ctx context.Context, composeFile, service string) (string, error) {
	path, err := o.resolve(composeFile)
	if err != nil {
		return "", err
	}
	args := []string{"kill"}
	if service != "" {
		args = append(args, service)
	}
	return o.run(ctx, path, args...)
}

// Exec runs `docker compose -f <file> exec -T <service> <args...>`. The -T
// flag disables TTY allocation so the call works in non-interactive contexts
// (CLI install, tests).
func (o *Orchestrator) Exec(ctx context.Context, composeFile, service string, args ...string) (string, error) {
	path, err := o.resolve(composeFile)
	if err != nil {
		return "", err
	}
	full := append([]string{"-T", service}, args...)
	return o.run(ctx, path, append([]string{"exec"}, full...)...)
}

// ExecAsUser is like Exec but runs the command as the given UID/GID inside the container.
// Use "www-data" for nextcloud's occ tool.
func (o *Orchestrator) ExecAsUser(ctx context.Context, composeFile, service, user string, args ...string) (string, error) {
	path, err := o.resolve(composeFile)
	if err != nil {
		return "", err
	}
	full := append([]string{"-T", "--user", user, service}, args...)
	return o.run(ctx, path, append([]string{"exec"}, full...)...)
}

// Status reports whether any service in the compose project is running.
func (o *Orchestrator) Status(ctx context.Context, composeFile string) (State, error) {
	path, err := o.resolve(composeFile)
	if err != nil {
		return StateUnknown, err
	}
	out, err := o.run(ctx, path, "ps", "--format", "json")
	if err != nil {
		return StateUnknown, err
	}
	out = strings.TrimSpace(out)
	if out == "" || out == "[]" {
		return StateStopped, nil
	}
	// docker compose ps emits either a JSON array OR newline-separated objects.
	if strings.HasPrefix(out, "[") {
		var arr []map[string]any
		if err := json.Unmarshal([]byte(out), &arr); err != nil {
			return StateUnknown, fmt.Errorf("parse ps json: %w", err)
		}
		return inferState(arr), nil
	}
	var rows []map[string]any
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			return StateUnknown, fmt.Errorf("parse ps line: %w", err)
		}
		rows = append(rows, m)
	}
	return inferState(rows), nil
}

func inferState(rows []map[string]any) State {
	if len(rows) == 0 {
		return StateStopped
	}
	for _, r := range rows {
		if s, _ := r["State"].(string); strings.EqualFold(s, "running") {
			return StateRunning
		}
	}
	return StateStopped
}

func (o *Orchestrator) resolve(composeFile string) (string, error) {
	if composeFile == "" {
		return "", fmt.Errorf("compose_file is empty")
	}
	if filepath.IsAbs(composeFile) {
		return composeFile, nil
	}
	if o.ComposeRoot == "" {
		return "", fmt.Errorf("compose_file is relative but orchestrator.compose_root is empty")
	}
	return filepath.Join(o.ComposeRoot, composeFile), nil
}

// run invokes `<DockerCompose...> -f <file> <args...>` and returns combined output.
func (o *Orchestrator) run(ctx context.Context, file string, args ...string) (string, error) {
	if len(o.DockerCompose) == 0 {
		return "", fmt.Errorf("docker_compose is unset")
	}
	argv := append([]string{}, o.DockerCompose[1:]...)
	argv = append(argv, "-f", file)
	argv = append(argv, args...)
	cmd := exec.CommandContext(ctx, o.DockerCompose[0], argv...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w (%s)", o.DockerCompose[0], strings.Join(argv, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
