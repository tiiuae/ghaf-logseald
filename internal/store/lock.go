// SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func Lock(root string, writer bool) (func(), error) {
	operation := syscall.LOCK_SH
	f, err := os.Open(root)
	if writer {
		if err == nil {
			_ = f.Close()
		}
		f, err = os.OpenFile(filepath.Join(root, "writer.lock"), os.O_CREATE|os.O_RDWR, 0o640)
		operation = syscall.LOCK_EX | syscall.LOCK_NB
	}
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), operation); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("lock state: %w", err)
	}
	return func() { _ = f.Close() }, nil
}

func lockMutation(root string) (func(), error) {
	f, err := os.Open(root)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() { _ = f.Close() }, nil
}
