package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/google/go-github/v68/github"
	"github.com/th3-j0ik3r/github-pat-monitor/internal/verify"
	"golang.org/x/oauth2"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: verify-test <org> [repo...]\n")
		os.Exit(1)
	}
	org := os.Args[1]

	// Get token from gh CLI
	tokenOut, err := exec.Command("gh", "auth", "token").Output()
	if err != nil {
		log.Fatalf("gh auth token: %v", err)
	}
	token := strings.TrimSpace(string(tokenOut))

	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(context.Background(), ts)
	client := github.NewClient(tc)

	repos := os.Args[2:]
	if len(repos) == 0 {
		cmd := exec.Command("gh", "api", fmt.Sprintf("orgs/%s/repos", org), "--jq", ".[].name")
		out, err := cmd.Output()
		if err != nil {
			log.Fatalf("list repos: %v", err)
		}
		repos = strings.Fields(strings.TrimSpace(string(out)))
	}

	orch := verify.NewOrchestrator(org, client)

	for _, repo := range repos {
		cmd := exec.Command("gh", "api",
			fmt.Sprintf("repos/%s/%s/actions/secrets", org, repo),
			"--jq", ".secrets[].name")
		out, err := cmd.Output()
		if err != nil {
			log.Printf("[%s] skip: %v", repo, err)
			continue
		}
		names := strings.Fields(strings.TrimSpace(string(out)))
		if len(names) == 0 {
			log.Printf("[%s] no secrets, skipping", repo)
			continue
		}

		log.Printf("[%s] verifying %d secrets: %v", repo, len(names), names)
		result, err := orch.VerifyRepo(context.Background(), repo, names, nil)
		if err != nil {
			log.Printf("[%s] FAILED: %v", repo, err)
			continue
		}

		j, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(j))
		fmt.Println()
	}
}
