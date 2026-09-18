// SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

type Limits struct {
	Bytes         int64
	Entries       int
	ChainBytes    int64
	ChainEntries  int
	WindowEntries int
	Compact       bool
}

var ErrCapacity = errors.New("logseald evidence capacity reached; provision capacity before resuming")

func ProducerLimits() Limits { return Limits{Bytes: 256 << 20, Entries: 100000} }
func SealerLimits() Limits {
	return Limits{Bytes: 1 << 30, Entries: 100000, ChainBytes: 128 << 20, ChainEntries: 20000}
}

func chooseLimits(defaults Limits, supplied []Limits) (Limits, error) {
	if len(supplied) > 1 {
		return Limits{}, fmt.Errorf("expected one storage policy")
	}
	if len(supplied) == 1 {
		defaults = supplied[0]
	}
	if defaults.Bytes < 1 || defaults.Entries < 1 || defaults.ChainBytes < 0 || defaults.ChainEntries < 0 || defaults.WindowEntries < 0 || defaults.WindowEntries > defaults.Entries {
		return Limits{}, fmt.Errorf("invalid storage policy")
	}
	return defaults, nil
}

func artifactNames(dir string, limit int) ([]string, int64, error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	var names []string
	var size int64
	count := 0
	// Bound directory allocation and count crash leftovers against capacity too.
	for {
		entries, err := f.ReadDir(256)
		for _, entry := range entries {
			count++
			if count > limit {
				return nil, 0, ErrCapacity
			}
			info, err := entry.Info()
			if err != nil {
				return nil, 0, err
			}
			if !info.Mode().IsRegular() {
				return nil, 0, fmt.Errorf("non-regular evidence file: %s", entry.Name())
			}
			if info.Size() > 90<<20 {
				return nil, 0, fmt.Errorf("evidence file too large: %s", entry.Name())
			}
			size += info.Size()
			if filepath.Ext(entry.Name()) == ".json" {
				names = append(names, entry.Name())
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, 0, err
		}
	}
	sort.Strings(names)
	return names, size, nil
}

func evidenceBytes(limits Limits, dirs ...string) (int64, error) {
	var total int64
	for _, dir := range dirs {
		_, size, err := artifactNames(dir, limits.Entries+1)
		if err != nil {
			return 0, err
		}
		if size > limits.Bytes-total {
			return 0, ErrCapacity
		}
		total += size
	}
	return total, nil
}

func readArtifact(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 90<<20 {
		return nil, fmt.Errorf("invalid evidence file %s", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, (90<<20)+1))
	if len(data) > 90<<20 {
		return nil, fmt.Errorf("evidence file too large")
	}
	return data, err
}
