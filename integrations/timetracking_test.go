// Copyright 2017 The Gitea Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package integrations

import (
	"net/http"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestViewTimetrackingControls(t *testing.T) {
	prepareTestEnv(t)
	session := loginUser(t, "user2")
	testViewTimetrackingControls(t, session, "user2", "repo1", "1", true)
	//user2/repo1
}

func TestNotViewTimetrackingControls(t *testing.T) {
	prepareTestEnv(t)
	session := loginUser(t, "user5")
	testViewTimetrackingControls(t, session, "user2", "repo1", "1", false)
	//user2/repo1
}
func TestViewTimetrackingControlsDisabled(t *testing.T) {
	prepareTestEnv(t)
	session := loginUser(t, "user2")
	testViewTimetrackingControls(t, session, "user3", "repo3", "1", false)
}

func testViewTimetrackingControls(t *testing.T, session *TestSession, user, repo, issue string, canTrackTime bool) {
	req := NewRequest(t, "GET", path.Join(user, repo, "issues", issue))
	resp := session.MakeRequest(t, req, http.StatusOK)

	htmlDoc := NewHTMLParser(t, resp.Body)

	htmlDoc.AssertElement(t, ".timetrack .start-add .start", canTrackTime)
	htmlDoc.AssertElement(t, ".timetrack .start-add .add-time", canTrackTime)

	req = NewRequestWithValues(t, "POST", path.Join(user, repo, "issues", issue, "times", "stopwatch", "toggle"), map[string]string{
		"_csrf": htmlDoc.GetCSRF(),
	})
	if canTrackTime {
		resp = session.MakeRequest(t, req, http.StatusSeeOther)

		req = NewRequest(t, "GET", RedirectURL(t, resp))
		resp = session.MakeRequest(t, req, http.StatusOK)
		htmlDoc = NewHTMLParser(t, resp.Body)

		events := htmlDoc.doc.Find(".event > span.text")
		assert.Contains(t, events.Last().Text(), "started working")

		htmlDoc.AssertElement(t, ".timetrack .stop-cancel .stop", true)
		htmlDoc.AssertElement(t, ".timetrack .stop-cancel .cancel", true)

		req = NewRequestWithValues(t, "POST", path.Join(user, repo, "issues", issue, "times", "stopwatch", "toggle"), map[string]string{
			"_csrf": htmlDoc.GetCSRF(),
		})
		resp = session.MakeRequest(t, req, http.StatusSeeOther)

		req = NewRequest(t, "GET", RedirectURL(t, resp))
		resp = session.MakeRequest(t, req, http.StatusOK)
		htmlDoc = NewHTMLParser(t, resp.Body)

		events = htmlDoc.doc.Find(".event > span.text")
		assert.Contains(t, events.Last().Text(), "stopped working")
		htmlDoc.AssertElement(t, ".event .detail .octicon-clock", true)
	} else {
		session.MakeRequest(t, req, http.StatusNotFound)
	}
}

// AssertElement check if element by selector exists or does not exist depending on checkExists
func (doc *HTMLDoc) AssertElement(t testing.TB, selector string, checkExists bool) {
	sel := doc.doc.Find(selector)
	if checkExists {
		assert.Equal(t, 1, sel.Length())
	} else {
		assert.Equal(t, 0, sel.Length())
	}
}
