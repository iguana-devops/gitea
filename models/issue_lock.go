// Copyright 2018 The Gitea Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package models

// LockIssue locks an issue. This would limit commenting abilities to
// users with write access to the repo
func LockIssue(user *User, issue *Issue) error {
	issue.IsLocked = true
	return lockOrUnlockIssue(user, issue, CommentTypeLock)
}

// UnlockIssue unlocks a previously locked issue.
func UnlockIssue(user *User, issue *Issue) error {
	issue.IsLocked = false
	return lockOrUnlockIssue(user, issue, CommentTypeUnlock)
}

func lockOrUnlockIssue(user *User, issue *Issue, commentType CommentType) error {
	if err := UpdateIssueCols(issue, "is_locked"); err != nil {
		return err
	}

	_, err := CreateComment(&CreateCommentOptions{
		Doer:  user,
		Issue: issue,
		Repo:  issue.Repo,
		Type:  commentType,
	})
	return err
}
