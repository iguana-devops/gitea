// Copyright 2021 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package v1_15 //nolint

import (
	"context"
	"fmt"

	"code.gitea.io/gitea/models/migrations/base"

	"xorm.io/xorm"
)

func RenameTaskErrorsToMessage(x *xorm.Engine) error {
	type Task struct {
		Errors string `xorm:"TEXT"` // if task failed, saved the error reason
		Type   int
		Status int `xorm:"index"`
	}

	// This migration maybe rerun so that we should check if it has been run
	messageExist, err := x.Dialect().IsColumnExist(x.DB(), context.Background(), "task", "message")
	if err != nil {
		return err
	}

	if messageExist {
		errorsExist, err := x.Dialect().IsColumnExist(x.DB(), context.Background(), "task", "errors")
		if err != nil {
			return err
		}
		if !errorsExist {
			return nil
		}
	}

	sess := x.NewSession()
	defer sess.Close()
	if err := sess.Begin(); err != nil {
		return err
	}

	if err := sess.Sync2(new(Task)); err != nil {
		return fmt.Errorf("error on Sync2: %w", err)
	}

	if messageExist {
		// if both errors and message exist, drop message at first
		if err := base.DropTableColumns(sess, "task", "message"); err != nil {
			return err
		}
	}

	if err := base.RenameColumn(sess, "task", "errors", "message", "text"); err != nil {
		return err
	}

	return sess.Commit()
}
