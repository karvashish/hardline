package remote

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestMutationLock_NilClientIsNoop(t *testing.T) {
	if err := AcquireMutationLock(nil); err != nil {
		t.Fatalf("expected nil client to be a no-op, got %v", err)
	}
	if err := ReleaseMutationLock(nil); err != nil {
		t.Fatalf("expected nil client to be a no-op, got %v", err)
	}
}

func TestMutationLock_AcquireAndRelease(t *testing.T) {
	prevNewSession := newSession
	defer func() { newSession = prevNewSession }()

	var sessions []*fakeSession
	newSession = func(*ssh.Client) (session, error) {
		sess := &fakeSession{stdoutText: lockTakenMarker + "\n"}
		sessions = append(sessions, sess)
		return sess, nil
	}

	c := New(nil)
	if err := AcquireMutationLock(c); err != nil {
		t.Fatalf("AcquireMutationLock failed: %v", err)
	}
	if err := ReleaseMutationLock(c); err != nil {
		t.Fatalf("ReleaseMutationLock failed: %v", err)
	}

	if len(sessions) != 2 {
		t.Fatalf("expected two remote commands, got %d", len(sessions))
	}
	if !strings.Contains(sessions[0].cmd, "&& mkdir ") || !strings.Contains(sessions[0].cmd, MutationLockDir) {
		t.Fatalf("expected an atomic mkdir of the lock dir, got %q", sessions[0].cmd)
	}
	if strings.Contains(sessions[0].cmd, "mkdir -p "+MutationLockDir) {
		t.Fatalf("lock dir must not be created with -p, got %q", sessions[0].cmd)
	}
	if !strings.Contains(sessions[1].cmd, "rmdir ") || !strings.Contains(sessions[1].cmd, MutationLockDir) {
		t.Fatalf("expected the lock dir to be removed, got %q", sessions[1].cmd)
	}
}

func TestMutationLock_ContentionNamesBothCommands(t *testing.T) {
	prevNewSession := newSession
	defer func() { newSession = prevNewSession }()

	newSession = func(*ssh.Client) (session, error) {
		return &fakeSession{stdoutText: "mkdir: File exists\n" + lockHeldMarker + "\n"}, nil
	}

	err := AcquireMutationLock(New(nil))
	if err == nil {
		t.Fatal("expected a held lock to fail acquisition")
	}
	for _, want := range []string{"apply or rollback", MutationLockDir} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected error to mention %q, got %v", want, err)
		}
	}
}

func TestMutationLock_UnrelatedFailureIsNotReportedAsContention(t *testing.T) {
	prevNewSession := newSession
	defer func() { newSession = prevNewSession }()

	newSession = func(*ssh.Client) (session, error) {
		return &fakeSession{stdoutText: "mkdir: cannot create directory '/var/lib/hardline': Read-only file system\n"}, nil
	}

	err := AcquireMutationLock(New(nil))
	if err == nil {
		t.Fatal("expected a failed mkdir to fail acquisition")
	}
	if strings.Contains(err.Error(), "apply or rollback") {
		t.Fatalf("expected the real cause, not a contention message, got %v", err)
	}
	if !strings.Contains(err.Error(), "Read-only file system") {
		t.Fatalf("expected the underlying mkdir failure to survive, got %v", err)
	}
}

func TestMutationLock_SessionErrorSurvives(t *testing.T) {
	prevNewSession := newSession
	defer func() { newSession = prevNewSession }()

	newSession = func(*ssh.Client) (session, error) {
		return &fakeSession{runErr: errors.New("connection lost")}, nil
	}

	err := AcquireMutationLock(New(nil))
	if err == nil || !strings.Contains(err.Error(), "connection lost") {
		t.Fatalf("expected the transport error to survive, got %v", err)
	}
}
