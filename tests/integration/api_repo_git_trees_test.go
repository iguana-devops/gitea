// Copyright 2019 The Gitea Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package integration

import (
	"net/http"
	"testing"

	repo_model "code.gitea.io/gitea/models/repo"
	"code.gitea.io/gitea/models/unittest"
	user_model "code.gitea.io/gitea/models/user"
	"code.gitea.io/gitea/tests"
)

func TestAPIReposGitTrees(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}).(*user_model.User)               // owner of the repo1 & repo16
	user3 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3}).(*user_model.User)               // owner of the repo3
	user4 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4}).(*user_model.User)               // owner of neither repos
	repo1 := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1}).(*repo_model.Repository)   // public repo
	repo3 := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3}).(*repo_model.Repository)   // public repo
	repo16 := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 16}).(*repo_model.Repository) // private repo
	repo1TreeSHA := "65f1bf27bc3bf70f64657658635e66094edbcb4d"
	repo3TreeSHA := "2a47ca4b614a9f5a43abbd5ad851a54a616ffee6"
	repo16TreeSHA := "69554a64c1e6030f051e5c3f94bfbd773cd6a324"
	badSHA := "0000000000000000000000000000000000000000"

	// Login as User2.
	session := loginUser(t, user2.Name)
	token := getTokenForLoggedInUser(t, session)
	session = emptyTestSession(t) // don't want anyone logged in for this

	// Test a public repo that anyone can GET the tree of
	for _, ref := range [...]string{
		"master",     // Branch
		repo1TreeSHA, // Tree SHA
	} {
		req := NewRequestf(t, "GET", "/api/v1/repos/%s/%s/git/trees/%s", user2.Name, repo1.Name, ref)
		session.MakeRequest(t, req, http.StatusOK)
	}

	// Tests a private repo with no token so will fail
	for _, ref := range [...]string{
		"master",     // Branch
		repo1TreeSHA, // Tag
	} {
		req := NewRequestf(t, "GET", "/api/v1/repos/%s/%s/git/trees/%s", user2.Name, repo16.Name, ref)
		session.MakeRequest(t, req, http.StatusNotFound)
	}

	// Test using access token for a private repo that the user of the token owns
	req := NewRequestf(t, "GET", "/api/v1/repos/%s/%s/git/trees/%s?token=%s", user2.Name, repo16.Name, repo16TreeSHA, token)
	session.MakeRequest(t, req, http.StatusOK)

	// Test using bad sha
	req = NewRequestf(t, "GET", "/api/v1/repos/%s/%s/git/trees/%s", user2.Name, repo1.Name, badSHA)
	session.MakeRequest(t, req, http.StatusBadRequest)

	// Test using org repo "user3/repo3" where user2 is a collaborator
	req = NewRequestf(t, "GET", "/api/v1/repos/%s/%s/git/trees/%s?token=%s", user3.Name, repo3.Name, repo3TreeSHA, token)
	session.MakeRequest(t, req, http.StatusOK)

	// Test using org repo "user3/repo3" with no user token
	req = NewRequestf(t, "GET", "/api/v1/repos/%s/%s/git/trees/%s", user3.Name, repo3TreeSHA, repo3.Name)
	session.MakeRequest(t, req, http.StatusNotFound)

	// Login as User4.
	session = loginUser(t, user4.Name)
	token4 := getTokenForLoggedInUser(t, session)
	session = emptyTestSession(t) // don't want anyone logged in for this

	// Test using org repo "user3/repo3" where user4 is a NOT collaborator
	req = NewRequestf(t, "GET", "/api/v1/repos/%s/%s/git/trees/d56a3073c1dbb7b15963110a049d50cdb5db99fc?access=%s", user3.Name, repo3.Name, token4)
	session.MakeRequest(t, req, http.StatusNotFound)
}
