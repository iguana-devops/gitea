// Copyright 2023 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT
package v1_22 //nolint

import (
	"errors"
	"fmt"

	"code.gitea.io/gitea/modules/log"
	"code.gitea.io/gitea/modules/setting"

	"xorm.io/xorm"
)

func ExpandHashReferencesToSha256(x *xorm.Engine) error {
	alteredTables := [][2]string{
		{"commit_status", "context_hash"},
		{"comment", "commit_sha"},
		{"pull_request", "merge_base"},
		{"pull_request", "merged_commit_id"},
		{"review", "commit_id"},
		{"review_state", "commit_sha"},
		{"repo_archiver", "commit_id"},
		{"release", "sha1"},
		{"repo_indexer_status", "commit_sha"},
	}

	db := x.NewSession()
	defer db.Close()

	if err := db.Begin(); err != nil {
		return err
	}

	if !setting.Database.Type.IsSQLite3() {
		if setting.Database.Type.IsMSSQL() {
			// drop indexes that need to be re-created afterwards
			droppedIndexes := []string{
				"DROP INDEX commit_status.IDX_commit_status_context_hash",
				"DROP INDEX review_state.UQE_review_state_pull_commit_user",
				"DROP INDEX repo_archiver.UQE_repo_archiver_s",
			}
			for _, s := range droppedIndexes {
				_, err := db.Exec(s)
				if err != nil {
					return errors.New(s + " " + err.Error())
				}
			}
		}

		for _, alts := range alteredTables {
			s := fmt.Sprintf("ALTER TABLE `%s` ALTER COLUMN `%s` TYPE VARCHAR(64)", alts[0], alts[1])

			if setting.Database.Type.IsMySQL() {
				s = fmt.Sprintf("ALTER TABLE `%s` MODIFY COLUMN `%s` VARCHAR(64)", alts[0], alts[1])
			} else if setting.Database.Type.IsMSSQL() {
				s = fmt.Sprintf("ALTER TABLE `%s` ALTER COLUMN `%s` VARCHAR(64)", alts[0], alts[1])
			}
			_, err := db.Exec(s)
			if err != nil {
				return errors.New(s + " " + err.Error())
			}
		}

		if setting.Database.Type.IsMSSQL() {
			recreateIndexes := []string{
				"CREATE INDEX IDX_commit_status_context_hash ON commit_status(context_hash)",
				"CREATE UNIQUE INDEX UQE_review_state_pull_commit_user ON review_state(user_id, pull_id, commit_sha)",
				"CREATE UNIQUE INDEX UQE_repo_archiver_s ON repo_archiver(repo_id, type, commit_id)",
			}
			for _, s := range recreateIndexes {
				_, err := db.Exec(s)
				if err != nil {
					return errors.New(s + " " + err.Error())
				}
			}
		}
	}
	log.Debug("Updated database tables to hold SHA256 git hash references")

	return db.Commit()
}
