package cli

import "fmt"

func VersionCmd() {
	const version = "0.1.0"
	fmt.Println("hardline version", version)
}
