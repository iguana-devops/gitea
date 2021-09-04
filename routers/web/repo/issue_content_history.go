// Copyright 2021 The Gitea Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package repo

import (
	"bytes"
	"fmt"
	"html"
	"net/http"

	"code.gitea.io/gitea/models"
	"code.gitea.io/gitea/modules/context"
	"code.gitea.io/gitea/modules/log"
	"code.gitea.io/gitea/modules/timeutil"

	"github.com/sergi/go-diff/diffmatchpatch"
	"github.com/unknwon/i18n"
)

// GetContentHistoryOverview get overview
func GetContentHistoryOverview(ctx *context.Context) {
	issue := GetActionIssue(ctx)
	if issue == nil {
		return
	}

	lang := ctx.Data["Lang"].(string)
	ctx.JSON(http.StatusOK, map[string]interface{}{
		"i18n": map[string]interface{}{
			"textEdited":                   i18n.Tr(lang, "repo.issues.content_history.edited"),
			"textDeleteFromHistory":        i18n.Tr(lang, "repo.issues.content_history.delete_from_history"),
			"textDeleteFromHistoryConfirm": i18n.Tr(lang, "repo.issues.content_history.delete_from_history_confirm"),
			"textOptions":                  i18n.Tr(lang, "repo.issues.content_history.options"),
		},
		"historyCountMap": models.QueryIssueContentHistoryCountMap(issue.ID),
	})
}

// GetContentHistoryList  get list
func GetContentHistoryList(ctx *context.Context) {
	issue := GetActionIssue(ctx)
	commentID := ctx.FormInt64("comment_id")
	if issue == nil {
		return
	}

	items := models.FetchIssueContentHistoryList(issue.ID, commentID)

	lang := ctx.Data["Lang"].(string)
	var results []map[string]interface{}
	for _, item := range items {
		var actionText string
		if item.IsDeleted {
			actionTextDeleted := i18n.Tr(lang, "repo.issues.content_history.deleted")
			actionText = "<i data-history-is-deleted='1'>" + actionTextDeleted + "</i>"
		} else if item.IsFirstCreated {
			actionText = i18n.Tr(lang, "repo.issues.content_history.created")
		} else {
			actionText = i18n.Tr(lang, "repo.issues.content_history.edited")
		}
		timeSinceText := timeutil.TimeSinceUnix(item.EditedUnix, lang)
		results = append(results, map[string]interface{}{
			"name": fmt.Sprintf("<img class='ui avatar image' src='%s'><strong>%s</strong> %s %s",
				item.UserAvatarLink, html.EscapeString(item.UserName), actionText, timeSinceText),
			"value":     item.HistoryID,
			"isDeleted": item.IsDeleted,
		})
	}
	ctx.JSON(http.StatusOK, map[string]interface{}{
		"results": results,
	})
}

//GetContentHistoryDetail get detail
func GetContentHistoryDetail(ctx *context.Context) {
	issue := GetActionIssue(ctx)
	if issue == nil {
		return
	}
	historyID := ctx.FormInt64("history_id")

	history, prevHistory := models.GetIssueContentHistoryAndPrev(historyID)
	if history == nil {
		ctx.JSON(http.StatusNotFound, map[string]interface{}{
			"message": "Can not find the content history",
		})
		return
	}

	var prevHistoryID int64
	var prevHistoryContentText string
	if prevHistory != nil {
		prevHistoryID = prevHistory.ID
		prevHistoryContentText = prevHistory.ContentText
	}

	dmp := diffmatchpatch.New()
	diff := dmp.DiffMain(prevHistoryContentText, history.ContentText, true)
	diff = dmp.DiffCleanupEfficiency(diff)

	// use chroma to render the diff html
	diffHTMLBuf := bytes.Buffer{}
	diffHTMLBuf.WriteString("<pre class='chroma' style='tab-size: 4'>")
	for _, it := range diff {
		if it.Type == diffmatchpatch.DiffInsert {
			diffHTMLBuf.WriteString("<span class='gi'>")
			diffHTMLBuf.WriteString(html.EscapeString(it.Text))
			diffHTMLBuf.WriteString("</span>")
		} else if it.Type == diffmatchpatch.DiffDelete {
			diffHTMLBuf.WriteString("<span class='gd'>")
			diffHTMLBuf.WriteString(html.EscapeString(it.Text))
			diffHTMLBuf.WriteString("</span>")
		} else {
			diffHTMLBuf.WriteString(html.EscapeString(it.Text))
		}
	}
	diffHTMLBuf.WriteString("</pre>")

	ctx.JSON(http.StatusOK, map[string]interface{}{
		"historyId":     historyID,
		"prevHistoryId": prevHistoryID,
		"diffHtml":      diffHTMLBuf.String(),
	})
}

//SoftDeleteContentHistory soft delete
func SoftDeleteContentHistory(ctx *context.Context) {
	issue := GetActionIssue(ctx)
	if issue == nil {
		return
	}

	commentID := ctx.FormInt64("comment_id")
	historyID := ctx.FormInt64("history_id")

	canSoftDelete := false
	var comment *models.Comment
	var history *models.IssueContentHistory
	var err error
	if commentID != 0 {
		if comment, err = models.GetCommentByID(commentID); err != nil {
			log.Error("can not get comment for issue content history %v. err=%v", historyID, err)
			return
		}
	}
	if history, err = models.GetIssueContentHistoryByID(historyID); err != nil {
		log.Error("can not get issue content history %v. err=%v", historyID, err)
		return
	}
	if ctx.Repo.IsOwner() {
		canSoftDelete = true
	} else if ctx.Repo.CanWrite(models.UnitTypeIssues) {
		canSoftDelete = ctx.User.ID == history.PosterID
		if commentID == 0 {
			canSoftDelete = canSoftDelete && (ctx.User.ID == issue.PosterID)
			canSoftDelete = canSoftDelete && (history.IssueID == issue.ID)
		} else {
			canSoftDelete = canSoftDelete && (ctx.User.ID == comment.PosterID)
			canSoftDelete = canSoftDelete && (history.IssueID == issue.ID)
			canSoftDelete = canSoftDelete && (history.CommentID == comment.ID)
		}
	}

	if !canSoftDelete {
		ctx.JSON(http.StatusForbidden, map[string]interface{}{
			"message": "Can not delete the content history",
		})
		return
	}

	models.SoftDeleteIssueContentHistory(historyID)
	log.Debug("soft delete issue content history. issue=%d, comment=%d, history=%d", issue.ID, commentID, historyID)
	ctx.JSON(http.StatusOK, map[string]interface{}{
		"ok": true,
	})
}
