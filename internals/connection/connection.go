package connection

import (
	"os"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type Config struct {
	KeyPath string
	User    string
	Host    string
}

func NewSSHClient(cfg Config) (*ssh.Client, error) {
	key, err := os.ReadFile(cfg.KeyPath)
	if err != nil {
		return nil, err
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, err
	}

	config := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", cfg.Host+":22", config)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func NewSFTPClient(client *ssh.Client) (*sftp.Client, error) {
	return sftp.NewClient(client)
}
