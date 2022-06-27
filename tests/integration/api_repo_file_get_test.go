// Copyright 2022 The Gitea Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package integration

import (
	"net/http"
	"net/url"
	"os"
	"testing"

	api "code.gitea.io/gitea/modules/structs"
	"code.gitea.io/gitea/modules/util"
	"code.gitea.io/gitea/tests"

	"github.com/stretchr/testify/assert"
)

func TestAPIGetRawFileOrLFS(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	// Test with raw file
	req := NewRequest(t, "GET", "/api/v1/repos/user2/repo1/media/README.md")
	resp := MakeRequest(t, req, http.StatusOK)
	assert.Equal(t, "# repo1\n\nDescription for repo1", resp.Body.String())

	// Test with LFS
	onGiteaRun(t, func(t *testing.T, u *url.URL) {
		httpContext := NewAPITestContext(t, "user2", "repo-lfs-test")
		doAPICreateRepository(httpContext, false, func(t *testing.T, repository api.Repository) {
			u.Path = httpContext.GitPath()
			dstPath, err := os.MkdirTemp("", httpContext.Reponame)
			assert.NoError(t, err)
			defer util.RemoveAll(dstPath)

			u.Path = httpContext.GitPath()
			u.User = url.UserPassword("user2", userPassword)

			t.Run("Clone", doGitClone(dstPath, u))

			dstPath2, err := os.MkdirTemp("", httpContext.Reponame)
			assert.NoError(t, err)
			defer util.RemoveAll(dstPath2)

			t.Run("Partial Clone", doPartialGitClone(dstPath2, u))

			lfs, _ := lfsCommitAndPushTest(t, dstPath)

			reqLFS := NewRequest(t, "GET", "/api/v1/repos/user2/repo1/media/"+lfs)
			respLFS := MakeRequestNilResponseRecorder(t, reqLFS, http.StatusOK)
			assert.Equal(t, littleSize, respLFS.Length)

			doAPIDeleteRepository(httpContext)
		})
	})
}
