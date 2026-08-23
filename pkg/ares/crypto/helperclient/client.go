// SPDX-License-Identifier: Apache-2.0

package helperclient

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// ErrNotImplemented is returned by ops whose helper-side handler has
// not yet been added to cmd/openfhe-contract-helper. The Go-side API
// is stable so callers can wire phase code against it now; the C++
// implementation lands in a follow-up.
var ErrNotImplemented = errors.New("helperclient: op not yet implemented in helper")

// HelperError wraps an error returned by the helper's run() function.
type HelperError struct {
	Op  string
	Msg string
}

func (e *HelperError) Error() string {
	return fmt.Sprintf("helper op %q: %s", e.Op, e.Msg)
}

// Client is a one-helper-per-Client wrapper. Construct with Start;
// each method serializes one Request, sends it over stdin, and reads
// one envelope back. Methods are concurrency-safe — internally the
// client owns a mutex so multiple goroutines can submit ops without
// stepping on each other's stdin/stdout traffic.
//
// To avoid head-of-line blocking, callers that need parallelism should
// spawn multiple Clients (one per worker). The helper's stdin protocol
// is single-flight per process.
type Client struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	enc    *json.Encoder
	dec    *json.Decoder

	mu   sync.Mutex
	done bool
}

// Start launches the helper binary at binaryPath in daemon mode and
// returns a ready Client.
func Start(ctx context.Context, binaryPath string) (*Client, error) {
	cmd := exec.CommandContext(ctx, binaryPath, "--daemon")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	cmd.Stderr = os.Stderr // helper logs (including CKKS deserialize failures) surface in the caller's stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start helper: %w", err)
	}
	bufStdout := bufio.NewReader(stdout)
	c := &Client{
		cmd:    cmd,
		stdin:  stdin,
		stdout: bufStdout,
		enc:    json.NewEncoder(stdin),
		dec:    json.NewDecoder(bufStdout),
	}
	// Probe the helper's linked OpenFHE version. A mismatch with the
	// supported major.minor prefix means cross-process ciphertexts
	// risk hitting a "Ciphertext was not created in this CryptoContext"
	// error from OpenFHE (different versions can pick different
	// cyclotomic primes for the same nominal CKKS parameters and so
	// resolve to incompatible CryptoContext fingerprints).
	if v, vErr := c.Version(); vErr == nil && v != "" {
		if !strings.HasPrefix(v, SupportedOpenFHEVersionPrefix) {
			fmt.Fprintf(os.Stderr,
				"helperclient: warning: helper at %s is linked against OpenFHE %s, framework is tested against %sx; expect context fingerprint mismatches if peers run a different version\n",
				binaryPath, v, SupportedOpenFHEVersionPrefix,
			)
		}
	}
	return c, nil
}

// Close signals the helper to exit and waits for it.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.done {
		c.mu.Unlock()
		return nil
	}
	c.done = true
	c.mu.Unlock()
	_ = c.stdin.Close()
	return c.cmd.Wait()
}

// call sends req and decodes the daemon-mode envelope.
func (c *Client) call(req Request) (*Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done {
		return nil, errors.New("helperclient: client is closed")
	}
	if err := c.enc.Encode(req); err != nil {
		return nil, fmt.Errorf("encode %s: %w", req.Op, err)
	}
	var env envelope
	if err := c.dec.Decode(&env); err != nil {
		return nil, fmt.Errorf("decode %s response: %w", req.Op, err)
	}
	if env.Error != "" {
		return nil, &HelperError{Op: req.Op, Msg: env.Error}
	}
	if env.Result == nil {
		return nil, fmt.Errorf("helper op %q: empty response envelope", req.Op)
	}
	return env.Result, nil
}
