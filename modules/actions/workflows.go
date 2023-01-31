// Copyright 2022 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package actions

import (
	"bytes"
	"io"
	"strings"

	"code.gitea.io/gitea/modules/git"
	"code.gitea.io/gitea/modules/log"
	api "code.gitea.io/gitea/modules/structs"
	webhook_module "code.gitea.io/gitea/modules/webhook"

	"github.com/gobwas/glob"
	"github.com/nektos/act/pkg/jobparser"
	"github.com/nektos/act/pkg/model"
)

func ListWorkflows(commit *git.Commit) (git.Entries, error) {
	tree, err := commit.SubTree(".gitea/workflows")
	if _, ok := err.(git.ErrNotExist); ok {
		tree, err = commit.SubTree(".github/workflows")
	}
	if _, ok := err.(git.ErrNotExist); ok {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	entries, err := tree.ListEntriesRecursiveFast()
	if err != nil {
		return nil, err
	}

	ret := make(git.Entries, 0, len(entries))
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".yml") || strings.HasSuffix(entry.Name(), ".yaml") {
			ret = append(ret, entry)
		}
	}
	return ret, nil
}

func DetectWorkflows(commit *git.Commit, event webhook_module.HookEventType, payload api.Payloader) (map[string][]byte, error) {
	entries, err := ListWorkflows(commit)
	if err != nil {
		return nil, err
	}

	workflows := make(map[string][]byte, len(entries))
	for _, entry := range entries {
		f, err := entry.Blob().DataAsync()
		if err != nil {
			return nil, err
		}
		content, err := io.ReadAll(f)
		_ = f.Close()
		if err != nil {
			return nil, err
		}
		workflow, err := model.ReadWorkflow(bytes.NewReader(content))
		if err != nil {
			log.Warn("ignore invalid workflow %q: %v", entry.Name(), err)
			continue
		}
		events, err := jobparser.ParseRawOn(&workflow.RawOn)
		if err != nil {
			log.Warn("ignore invalid workflow %q: %v", entry.Name(), err)
			continue
		}
		for _, evt := range events {
			if evt.Name != event.Event() {
				continue
			}

			if detectMatched(commit, evt, event, payload) {
				workflows[entry.Name()] = content
			}
		}
	}

	return workflows, nil
}

func detectMatched(commit *git.Commit, triggedEvt *jobparser.Event, event webhook_module.HookEventType, payload api.Payloader) bool {
	if len(triggedEvt.Acts) == 0 {
		return true
	}

	switch event {
	case webhook_module.HookEventCreate:
		fallthrough
	case webhook_module.HookEventDelete:
		fallthrough
	case webhook_module.HookEventFork:
		log.Error("unsupported event %q", event.Event())
		return false
	case webhook_module.HookEventPush:
		pushPayload := payload.(*api.PushPayload)
		matchTimes := 0
		// all acts conditions should be satisfied
		for cond, vals := range triggedEvt.Acts {
			switch cond {
			case "branches", "tags":
				for _, val := range vals {
					if glob.MustCompile(val, '/').Match(pushPayload.Ref) {
						matchTimes++
						break
					}
				}
			case "paths":
				filesChanged := append(append(pushPayload.HeadCommit.Added,
					pushPayload.HeadCommit.Modified...),
					pushPayload.HeadCommit.Removed...)
				for _, val := range vals {
					matched := false
					for _, file := range filesChanged {
						if glob.MustCompile(val, '/').Match(file) {
							matched = true
							break
						}
					}
					if matched {
						matchTimes++
						break
					}
				}
			default:
				log.Warn("unsupported condition %q", cond)
			}
		}
		return matchTimes == len(triggedEvt.Acts)

	case webhook_module.HookEventIssues:
		fallthrough
	case webhook_module.HookEventIssueAssign:
		fallthrough
	case webhook_module.HookEventIssueLabel:
		fallthrough
	case webhook_module.HookEventIssueMilestone:
		fallthrough
	case webhook_module.HookEventIssueComment:
		fallthrough
	case webhook_module.HookEventPullRequest:
		prPayload := payload.(*api.PullRequestPayload)
		matchTimes := 0
		// all acts conditions should be satisfied
		for cond, vals := range triggedEvt.Acts {
			switch cond {
			case "types":
				for _, val := range vals {
					if glob.MustCompile(val, '/').Match(string(prPayload.Action)) {
						matchTimes++
						break
					}
				}
			case "branches":
				for _, val := range vals {
					if glob.MustCompile(val, '/').Match(prPayload.PullRequest.Base.Ref) {
						matchTimes++
						break
					}
				}
			case "paths":
				fallthrough
			default:
				log.Warn("unsupported condition %q", cond)
			}
		}
		return matchTimes == len(triggedEvt.Acts)
	case webhook_module.HookEventPullRequestAssign:
		fallthrough
	case webhook_module.HookEventPullRequestLabel:
		fallthrough
	case webhook_module.HookEventPullRequestMilestone:
		fallthrough
	case webhook_module.HookEventPullRequestComment:
		fallthrough
	case webhook_module.HookEventPullRequestReviewApproved:
		fallthrough
	case webhook_module.HookEventPullRequestReviewRejected:
		fallthrough
	case webhook_module.HookEventPullRequestReviewComment:
		fallthrough
	case webhook_module.HookEventPullRequestSync:
		fallthrough
	case webhook_module.HookEventWiki:
		fallthrough
	case webhook_module.HookEventRepository:
		fallthrough
	case webhook_module.HookEventRelease:
		fallthrough
	case webhook_module.HookEventPackage:
		fallthrough
	default:
		log.Error("unsupported event %q", event.Event())
	}
	return false
}
