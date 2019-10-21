// Copyright 2017 The Gitea Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package cmd

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"code.gitea.io/gitea/models"
	"code.gitea.io/gitea/modules/git"
	"code.gitea.io/gitea/modules/private"
	"code.gitea.io/gitea/modules/setting"

	"github.com/urfave/cli"
)

const (
	hookBatchSize = 30
)

var (
	// CmdHook represents the available hooks sub-command.
	CmdHook = cli.Command{
		Name:        "hook",
		Usage:       "Delegate commands to corresponding Git hooks",
		Description: "This should only be called by Git",
		Subcommands: []cli.Command{
			subcmdHookPreReceive,
			subcmdHookUpdate,
			subcmdHookPostReceive,
		},
	}

	subcmdHookPreReceive = cli.Command{
		Name:        "pre-receive",
		Usage:       "Delegate pre-receive Git hook",
		Description: "This command should only be called by Git",
		Action:      runHookPreReceive,
	}
	subcmdHookUpdate = cli.Command{
		Name:        "update",
		Usage:       "Delegate update Git hook",
		Description: "This command should only be called by Git",
		Action:      runHookUpdate,
	}
	subcmdHookPostReceive = cli.Command{
		Name:        "post-receive",
		Usage:       "Delegate post-receive Git hook",
		Description: "This command should only be called by Git",
		Action:      runHookPostReceive,
	}
)

func runHookPreReceive(c *cli.Context) error {
	if len(os.Getenv("SSH_ORIGINAL_COMMAND")) == 0 {
		if setting.OnlyAllowPushIfGiteaEnvironmentSet {
			fail(`Rejecting changes as Gitea environment not set.
If you are pushing over SSH you must push with a key managed by
Gitea or set your environment appropriately.`, "")
		} else {
			return nil
		}
	}

	setup("hooks/pre-receive.log")

	// the environment setted on serv command
	isWiki := (os.Getenv(models.EnvRepoIsWiki) == "true")
	username := os.Getenv(models.EnvRepoUsername)
	reponame := os.Getenv(models.EnvRepoName)
	userID, _ := strconv.ParseInt(os.Getenv(models.EnvPusherID), 10, 64)
	prID, _ := strconv.ParseInt(os.Getenv(models.ProtectedBranchPRID), 10, 64)
	isDeployKey, _ := strconv.ParseBool(os.Getenv(models.EnvIsDeployKey))

	hookOptions := private.HookOptions{
		UserID:                          userID,
		GitAlternativeObjectDirectories: os.Getenv(private.GitAlternativeObjectDirectories),
		GitObjectDirectory:              os.Getenv(private.GitObjectDirectory),
		GitQuarantinePath:               os.Getenv(private.GitQuarantinePath),
		ProtectedBranchID:               prID,
		IsDeployKey:                     isDeployKey,
	}

	scanner := bufio.NewScanner(os.Stdin)

	oldCommitIDs := make([]string, hookBatchSize)
	newCommitIDs := make([]string, hookBatchSize)
	refFullNames := make([]string, hookBatchSize)
	count := 0

	for scanner.Scan() {
		// TODO: support news feeds for wiki
		if isWiki {
			continue
		}

		fields := bytes.Fields(scanner.Bytes())
		if len(fields) != 3 {
			continue
		}

		oldCommitID := string(fields[0])
		newCommitID := string(fields[1])
		refFullName := string(fields[2])

		// If the ref is a branch, check if it's protected
		if strings.HasPrefix(refFullName, git.BranchPrefix) {
			oldCommitIDs[count] = oldCommitID
			newCommitIDs[count] = newCommitID
			refFullNames[count] = refFullName
			count++
			if count >= hookBatchSize {
				hookOptions.OldCommitIDs = oldCommitIDs
				hookOptions.NewCommitIDs = newCommitIDs
				hookOptions.RefFullNames = refFullNames
				statusCode, msg := private.HookPreReceive(username, reponame, hookOptions)
				switch statusCode {
				case http.StatusInternalServerError:
					fail("Internal Server Error", msg)
				case http.StatusForbidden:
					fail(msg, "")
				}
				count = 0
			}
		}
	}

	if count > 0 {
		hookOptions.OldCommitIDs = oldCommitIDs[:count]
		hookOptions.NewCommitIDs = newCommitIDs[:count]
		hookOptions.RefFullNames = refFullNames[:count]

		statusCode, msg := private.HookPreReceive(username, reponame, hookOptions)
		switch statusCode {
		case http.StatusInternalServerError:
			fail("Internal Server Error", msg)
		case http.StatusForbidden:
			fail(msg, "")
		}
	}

	return nil
}

func runHookUpdate(c *cli.Context) error {
	if len(os.Getenv("SSH_ORIGINAL_COMMAND")) == 0 {
		if setting.OnlyAllowPushIfGiteaEnvironmentSet {
			fail(`Rejecting changes as Gitea environment not set.
If you are pushing over SSH you must push with a key managed by
Gitea or set your environment appropriately.`, "")
		} else {
			return nil
		}
	}

	setup("hooks/update.log")

	return nil
}

func runHookPostReceive(c *cli.Context) error {
	if len(os.Getenv("SSH_ORIGINAL_COMMAND")) == 0 {
		if setting.OnlyAllowPushIfGiteaEnvironmentSet {
			fail(`Rejecting changes as Gitea environment not set.
If you are pushing over SSH you must push with a key managed by
Gitea or set your environment appropriately.`, "")
		} else {
			return nil
		}
	}

	setup("hooks/post-receive.log")

	// the environment setted on serv command
	repoUser := os.Getenv(models.EnvRepoUsername)
	isWiki := (os.Getenv(models.EnvRepoIsWiki) == "true")
	repoName := os.Getenv(models.EnvRepoName)
	pusherID, _ := strconv.ParseInt(os.Getenv(models.EnvPusherID), 10, 64)
	pusherName := os.Getenv(models.EnvPusherName)

	hookOptions := private.HookOptions{
		UserName:                        pusherName,
		UserID:                          pusherID,
		GitAlternativeObjectDirectories: os.Getenv(private.GitAlternativeObjectDirectories),
		GitObjectDirectory:              os.Getenv(private.GitObjectDirectory),
		GitQuarantinePath:               os.Getenv(private.GitQuarantinePath),
	}
	oldCommitIDs := make([]string, hookBatchSize)
	newCommitIDs := make([]string, hookBatchSize)
	refFullNames := make([]string, hookBatchSize)
	count := 0

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		// TODO: support news feeds for wiki
		if isWiki {
			continue
		}

		fields := bytes.Fields(scanner.Bytes())
		if len(fields) != 3 {
			continue
		}

		oldCommitIDs[count] = string(fields[0])
		newCommitIDs[count] = string(fields[1])
		refFullNames[count] = string(fields[2])
		count++

		if count >= hookBatchSize {
			hookOptions.OldCommitIDs = oldCommitIDs
			hookOptions.NewCommitIDs = newCommitIDs
			hookOptions.RefFullNames = refFullNames
			resps, err := private.HookPostReceive(repoUser, repoName, hookOptions)
			if resps == nil {
				fail("Internal Server Error", err)
			}
			for _, res := range resps {
				if !res.Message {
					continue
				}

				fmt.Fprintln(os.Stderr, "")
				if res.Create {
					fmt.Fprintf(os.Stderr, "Create a new pull request for '%s':\n", res.Branch)
					fmt.Fprintf(os.Stderr, "  %s\n", res.URL)
				} else {
					fmt.Fprint(os.Stderr, "Visit the existing pull request:\n")
					fmt.Fprintf(os.Stderr, "  %s\n", res.URL)
				}
				fmt.Fprintln(os.Stderr, "")
			}
			count = 0
		}
	}

	if count == 0 {
		return nil
	}

	hookOptions.OldCommitIDs = oldCommitIDs[:count]
	hookOptions.NewCommitIDs = newCommitIDs[:count]
	hookOptions.RefFullNames = refFullNames[:count]
	resps, err := private.HookPostReceive(repoUser, repoName, hookOptions)
	if resps == nil {
		fail("Internal Server Error", err)
	}
	for _, res := range resps {
		if !res.Message {
			continue
		}

		fmt.Fprintln(os.Stderr, "")
		if res.Create {
			fmt.Fprintf(os.Stderr, "Create a new pull request for '%s':\n", res.Branch)
			fmt.Fprintf(os.Stderr, "  %s\n", res.URL)
		} else {
			fmt.Fprint(os.Stderr, "Visit the existing pull request:\n")
			fmt.Fprintf(os.Stderr, "  %s\n", res.URL)
		}
		fmt.Fprintln(os.Stderr, "")
	}

	return nil
}
