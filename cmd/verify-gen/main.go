package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/th3-j0ik3r/github-pat-monitor/internal/verify"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "usage: verify-gen <repo> <repoSecret1,repoSecret2,...> [envName:secret1,secret2 ...]\n")
		os.Exit(1)
	}
	repo := os.Args[1]
	var repoSecrets []string
	if os.Args[2] != "" {
		repoSecrets = strings.Split(os.Args[2], ",")
	}

	var envGroups []verify.EnvironmentSecrets
	for _, arg := range os.Args[3:] {
		envName, names, ok := strings.Cut(arg, ":")
		if !ok {
			fmt.Fprintf(os.Stderr, "invalid environment arg %q, expected envName:secret1,secret2\n", arg)
			os.Exit(1)
		}
		envGroups = append(envGroups, verify.EnvironmentSecrets{
			EnvName: envName,
			Names:   strings.Split(names, ","),
		})
	}

	fmt.Print(verify.GenerateWorkflow(repo, repoSecrets, envGroups))
}
