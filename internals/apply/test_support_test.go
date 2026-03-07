package apply

import (
	"os"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func stubStepDeps() func() {
	prevRunRoot := runRootCmd
	prevRunRootOut := runRootCmdWithOutput
	prevReadRoot := readRootFile
	prevNewSFTP := newSFTPClient
	prevWriteRoot := writeRootFile
	prevServiceDirty := serviceDirty
	resetApplyStepState()
	runRootCmd = func(_ *ssh.Client, _ string) error { return nil }
	runRootCmdWithOutput = func(_ *ssh.Client, _ string) (string, error) { return "", nil }
	readRootFile = func(_ *ssh.Client, _ string) (string, error) { return "", nil }
	newSFTPClient = func(_ *ssh.Client) (*sftp.Client, error) { return nil, nil }
	writeRootFile = func(_ *ssh.Client, _ *sftp.Client, _ string, _ []byte, _ os.FileMode) error { return nil }

	return func() {
		runRootCmd = prevRunRoot
		runRootCmdWithOutput = prevRunRootOut
		readRootFile = prevReadRoot
		newSFTPClient = prevNewSFTP
		writeRootFile = prevWriteRoot
		serviceDirty = prevServiceDirty
	}
}
