// Copyright 2021 Gitea. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package models

import (
	repo_model "code.gitea.io/gitea/models/repo"
	user_model "code.gitea.io/gitea/models/user"
	"code.gitea.io/gitea/modules/git"
)

// ConvertFromGitCommit converts git commits into SignCommitWithStatuses
func ConvertFromGitCommit(commits []*git.Commit, repo *repo_model.Repository) []*SignCommitWithStatuses {
	return ParseCommitsWithStatus(
		ParseCommitsWithSignature(
			user_model.ValidateCommitsWithEmails(commits),
			repo,
		),
		repo,
	)
}
