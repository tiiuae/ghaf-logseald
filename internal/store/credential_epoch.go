// SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/tiiuae/ghaf-logseald/internal/durable"
)

// The caller holds the writer lock across preparation and daemon startup.
func PrepareCredentialEpoch(root, role, epoch string) (bool, error) {
	var paths []string
	switch role {
	case "producer":
		paths = []string{"queue", "sealed", "boundary.json", "sealer-public-key"}
	case "sealer":
		paths = []string{"ledger", "checkpoint.json", "compact-format", "sealer.key"}
	default:
		return false, fmt.Errorf("invalid credential epoch role")
	}
	if decoded, err := hex.DecodeString(epoch); err != nil || len(decoded) != 32 {
		return false, fmt.Errorf("invalid credential epoch digest")
	}
	unlock, err := lockMutation(root)
	if err != nil {
		return false, err
	}
	defer unlock()
	marker := filepath.Join(root, "credential-epoch")
	expected := []byte(role + ":" + epoch + "\n")
	f, err := os.Open(marker)
	if err == nil {
		previous, readErr := io.ReadAll(io.LimitReader(f, int64(len(expected)+1)))
		_ = f.Close()
		if readErr != nil {
			return false, readErr
		}
		if bytes.Equal(previous, expected) {
			return false, nil
		}
		prefix := []byte(role + ":")
		if len(previous) != len(expected) || !bytes.HasPrefix(previous, prefix) || previous[len(previous)-1] != '\n' {
			return false, fmt.Errorf("invalid credential epoch marker")
		}
		if _, err := hex.DecodeString(string(previous[len(prefix) : len(previous)-1])); err != nil {
			return false, fmt.Errorf("invalid credential epoch marker: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	for _, name := range paths {
		if err := os.RemoveAll(filepath.Join(root, name)); err != nil {
			return false, fmt.Errorf("discard previous %s state: %w", role, err)
		}
	}
	if err := durable.SyncDir(root); err != nil {
		return false, err
	}
	if err := durable.WriteFile(marker, expected, 0o640); err != nil {
		return false, err
	}
	return true, nil
}
