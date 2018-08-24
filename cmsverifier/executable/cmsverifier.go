// Package executablecsrverifier defines the ExecutableCMSVerifier csrverifier.CMSVerifier.
package executablecmsverifier

import (
	"errors"
	"os"
	"os/exec"

	"bytes"
	"github.com/go-kit/kit/log"
)

const (
	userExecute os.FileMode = 1 << (6 - 3*iota)
	groupExecute
	otherExecute
)

// New creates a executablecsrverifier.ExecutableCMSVerifier.
func New(path string, logger log.Logger) (*ExecutableCMSVerifier, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	fileMode := fileInfo.Mode()
	if fileMode.IsDir() {
		return nil, errors.New("CMS Verifier executable is a directory")
	}

	filePerm := fileMode.Perm()
	if filePerm&(userExecute|groupExecute|otherExecute) == 0 {
		return nil, errors.New("CMS Verifier executable is not executable")
	}

	return &ExecutableCMSVerifier{executable: path, logger: logger}, nil
}

// ExecutableCMSVerifier implements a csrverifier.CMSVerifier.
// It executes a command, and passes it the raw decrypted CMS.
// If the command exit code is 0, the CMS is considered valid.
// In any other cases, the CMS is considered invalid.
type ExecutableCMSVerifier struct {
	executable string
	logger     log.Logger
}

func (v *ExecutableCMSVerifier) Verify(data []byte) (bool, error) {
	cmd := exec.Command(v.executable)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return false, err
	}

	go func() {
		defer stdin.Close()
		stdin.Write(data)
	}()

	err = cmd.Run()
	if err != nil {
		v.logger.Log("err", err)
		v.logger.Log("err", out.String())
		v.logger.Log("err", stderr.String())
		// mask the executable error
		return false, nil
	}
	return true, err
}
