package cli

type Command struct {
	Name    string
	Profile string
	Host    string
	User    string
	KeyPath string
	Debug   bool
}
