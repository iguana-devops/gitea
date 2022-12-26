// Copyright 2020 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package board

import (
	"context"
	"fmt"

	"code.gitea.io/gitea/models/db"
	"code.gitea.io/gitea/modules/log"
)

// BoardIssue saves relation from issue to a board
type BoardIssue struct { //revive:disable-line:exported
	ID      int64 `xorm:"pk autoincr"`
	IssueID int64 `xorm:"INDEX"`
	BoardID int64 `xorm:"INDEX"`

	// If 0, then it has not been added to a specific board in the board
	BoardColumnID int64 `xorm:"INDEX"`

	// the sorting order on the board
	Sorting int64 `xorm:"NOT NULL DEFAULT 0"`
}

func init() {
	db.RegisterModel(new(BoardIssue))
}

func deleteBoardIssuesByBoardID(ctx context.Context, boardID int64) error {
	_, err := db.GetEngine(ctx).Where("board_id=?", boardID).Delete(&BoardIssue{})
	return err
}

// NumIssues return counter of all issues assigned to a board
func (p *Board) NumIssues() int {
	c, err := db.GetEngine(db.DefaultContext).Table("board_issue").
		Where("board_id=?", p.ID).
		GroupBy("issue_id").
		Cols("issue_id").
		Count()
	if err != nil {
		log.Error("NumIssues: %v", err)
		return 0
	}
	return int(c)
}

// NumClosedIssues return counter of closed issues assigned to a board
func (p *Board) NumClosedIssues() int {
	c, err := db.GetEngine(db.DefaultContext).Table("board_issue").
		Join("INNER", "issue", "board_issue.issue_id=issue.id").
		Where("board_issue.board_id=? AND issue.is_closed=?", p.ID, true).
		Cols("issue_id").
		Count()
	if err != nil {
		log.Error("NumClosedIssues: %v", err)
		return 0
	}
	return int(c)
}

// NumOpenIssues return counter of open issues assigned to a board
func (p *Board) NumOpenIssues() int {
	c, err := db.GetEngine(db.DefaultContext).Table("board_issue").
		Join("INNER", "issue", "board_issue.issue_id=issue.id").
		Where("board_issue.board_id=? AND issue.is_closed=?", p.ID, false).
		Cols("issue_id").
		Count()
	if err != nil {
		log.Error("NumOpenIssues: %v", err)
		return 0
	}
	return int(c)
}

// MoveIssuesOnBoardColumn moves or keeps issues in a column and sorts them inside that column
func MoveIssuesOnBoardColumn(column *Column, sortedIssueIDs map[int64]int64) error {
	return db.WithTx(db.DefaultContext, func(ctx context.Context) error {
		sess := db.GetEngine(ctx)

		issueIDs := make([]int64, 0, len(sortedIssueIDs))
		for _, issueID := range sortedIssueIDs {
			issueIDs = append(issueIDs, issueID)
		}
		count, err := sess.Table(new(BoardIssue)).Where("board_id=?", column.BoardID).In("issue_id", issueIDs).Count()
		if err != nil {
			return err
		}
		if int(count) != len(sortedIssueIDs) {
			return fmt.Errorf("all issues have to be added to a board first")
		}

		for sorting, issueID := range sortedIssueIDs {
			_, err = sess.Exec("UPDATE `board_issue` SET board_column_id=?, sorting=? WHERE issue_id=?", column.ID, sorting, issueID)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func (b *Column) removeIssues(ctx context.Context) error {
	_, err := db.GetEngine(ctx).Exec("UPDATE `board_issue` SET board_column_id = 0 WHERE board_column_id = ? ", b.ID)
	return err
}
