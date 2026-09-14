// SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os/exec"
	"testing"
	"time"
)

func TestStopJournalTerminatesAndReapsRunningProcess(t *testing.T) {
	command := exec.Command("sleep", "60")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill() })
	done := make(chan struct{})
	go func() { stopJournal(command); close(done) }()
	select {
	case <-done:
		if command.ProcessState == nil {
			t.Fatal("child was not reaped")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cleanup waited for a still-running journal process")
	}
}

func TestStopJournalReapsExitedProcess(t *testing.T) {
	command := exec.Command("true")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	stopJournal(command)
	if command.ProcessState == nil {
		t.Fatal("exited child was not reaped")
	}
}
