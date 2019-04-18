// Copyright 2019 The Gitea Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package integrations

import (
	"net/url"
	"testing"
	"time"

	"code.gitea.io/gitea/models"
	"code.gitea.io/gitea/modules/git"
	"code.gitea.io/gitea/modules/repofiles"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/modules/test"
	api "code.gitea.io/sdk/gitea"

	"github.com/stretchr/testify/assert"
)

func getCreateRepoFileOptions(repo *models.Repository) *repofiles.UpdateRepoFileOptions {
	return &repofiles.UpdateRepoFileOptions{
		OldBranch: repo.DefaultBranch,
		NewBranch: repo.DefaultBranch,
		TreePath:  "new/file.txt",
		Message:   "Creates new/file.txt",
		Content:   "This is a NEW file",
		IsNewFile: true,
		Author:    nil,
		Committer: nil,
	}
}

func getUpdateRepoFileOptions(repo *models.Repository) *repofiles.UpdateRepoFileOptions {
	return &repofiles.UpdateRepoFileOptions{
		OldBranch: repo.DefaultBranch,
		NewBranch: repo.DefaultBranch,
		TreePath:  "README.md",
		Message:   "Updates README.md",
		SHA:       "4b4851ad51df6a7d9f25c979345979eaeb5b349f",
		Content:   "This is UPDATED content for the README file",
		IsNewFile: false,
		Author:    nil,
		Committer: nil,
	}
}

func getExpectedFileResponseForRepofilesCreate(commitID string) *api.FileResponse {
	return &api.FileResponse{
		Content: &api.FileContentResponse{
			Name:        "file.txt",
			Path:        "new/file.txt",
			SHA:         "103ff9234cefeee5ec5361d22b49fbb04d385885",
			Size:        18,
			URL:         setting.AppURL + "api/v1/repos/user2/repo1/contents/new/file.txt",
			HTMLURL:     setting.AppURL + "user2/repo1/blob/master/new/file.txt",
			GitURL:      setting.AppURL + "api/v1/repos/user2/repo1/git/blobs/103ff9234cefeee5ec5361d22b49fbb04d385885",
			DownloadURL: setting.AppURL + "user2/repo1/raw/branch/master/new/file.txt",
			Type:        "blob",
			Links: &api.FileLinksResponse{
				Self:    setting.AppURL + "api/v1/repos/user2/repo1/contents/new/file.txt",
				GitURL:  setting.AppURL + "api/v1/repos/user2/repo1/git/blobs/103ff9234cefeee5ec5361d22b49fbb04d385885",
				HTMLURL: setting.AppURL + "user2/repo1/blob/master/new/file.txt",
			},
		},
		Commit: &api.FileCommitResponse{
			CommitMeta: api.CommitMeta{
				URL: setting.AppURL + "api/v1/repos/user2/repo1/git/commits/" + commitID,
				SHA: commitID,
			},
			HTMLURL: setting.AppURL + "user2/repo1/commit/" + commitID,
			Author: &api.CommitUser{
				Identity: api.Identity{
					Name:  "User Two",
					Email: "user2@noreply.example.org",
				},
				Date: time.Now().UTC().Format(time.RFC3339),
			},
			Committer: &api.CommitUser{
				Identity: api.Identity{
					Name:  "User Two",
					Email: "user2@noreply.example.org",
				},
				Date: time.Now().UTC().Format(time.RFC3339),
			},
			Parents: []*api.CommitMeta{
				{
					URL: setting.AppURL + "api/v1/repos/user2/repo1/git/commits/65f1bf27bc3bf70f64657658635e66094edbcb4d",
					SHA: "65f1bf27bc3bf70f64657658635e66094edbcb4d",
				},
			},
			Message: "Updates README.md\n",
			Tree: &api.CommitMeta{
				URL: setting.AppURL + "api/v1/repos/user2/repo1/git/trees/f93e3a1a1525fb5b91020da86e44810c87a2d7bc",
				SHA: "f93e3a1a1525fb5b91020git dda86e44810c87a2d7bc",
			},
		},
		Verification: &api.PayloadCommitVerification{
			Verified:  false,
			Reason:    "unsigned",
			Signature: "",
			Payload:   "",
		},
	}
}

func getExpectedFileResponseForRepofilesUpdate(commitID string) *api.FileResponse {
	return &api.FileResponse{
		Content: &api.FileContentResponse{
			Name:        "README.md",
			Path:        "README.md",
			SHA:         "dbf8d00e022e05b7e5cf7e535de857de57925647",
			Size:        43,
			URL:         setting.AppURL + "api/v1/repos/user2/repo1/contents/README.md",
			HTMLURL:     setting.AppURL + "user2/repo1/blob/master/README.md",
			GitURL:      setting.AppURL + "api/v1/repos/user2/repo1/git/blobs/dbf8d00e022e05b7e5cf7e535de857de57925647",
			DownloadURL: setting.AppURL + "user2/repo1/raw/branch/master/README.md",
			Type:        "blob",
			Links: &api.FileLinksResponse{
				Self:    setting.AppURL + "api/v1/repos/user2/repo1/contents/README.md",
				GitURL:  setting.AppURL + "api/v1/repos/user2/repo1/git/blobs/dbf8d00e022e05b7e5cf7e535de857de57925647",
				HTMLURL: setting.AppURL + "user2/repo1/blob/master/README.md",
			},
		},
		Commit: &api.FileCommitResponse{
			CommitMeta: api.CommitMeta{
				URL: setting.AppURL + "api/v1/repos/user2/repo1/git/commits/" + commitID,
				SHA: commitID,
			},
			HTMLURL: setting.AppURL + "user2/repo1/commit/" + commitID,
			Author: &api.CommitUser{
				Identity: api.Identity{
					Name:  "User Two",
					Email: "user2@noreply.example.org",
				},
				Date: time.Now().UTC().Format(time.RFC3339),
			},
			Committer: &api.CommitUser{
				Identity: api.Identity{
					Name:  "User Two",
					Email: "user2@noreply.example.org",
				},
				Date: time.Now().UTC().Format(time.RFC3339),
			},
			Parents: []*api.CommitMeta{
				{
					URL: setting.AppURL + "api/v1/repos/user2/repo1/git/commits/65f1bf27bc3bf70f64657658635e66094edbcb4d",
					SHA: "65f1bf27bc3bf70f64657658635e66094edbcb4d",
				},
			},
			Message: "Updates README.md\n",
			Tree: &api.CommitMeta{
				URL: setting.AppURL + "api/v1/repos/user2/repo1/git/trees/f93e3a1a1525fb5b91020da86e44810c87a2d7bc",
				SHA: "f93e3a1a1525fb5b91020da86e44810c87a2d7bc",
			},
		},
		Verification: &api.PayloadCommitVerification{
			Verified:  false,
			Reason:    "unsigned",
			Signature: "",
			Payload:   "",
		},
	}
}

func TestCreateOrUpdateRepoFileForCreate(t *testing.T) {
	// setup
	onGiteaRun(t, func(t *testing.T, u *url.URL) {
		ctx := test.MockContext(t, "user2/repo1")
		ctx.SetParams(":id", "1")
		test.LoadRepo(t, ctx, 1)
		test.LoadRepoCommit(t, ctx)
		test.LoadUser(t, ctx, 2)
		test.LoadGitRepo(t, ctx)
		repo := ctx.Repo.Repository
		doer := ctx.User
		opts := getCreateRepoFileOptions(repo)

		// test
		fileResponse, err := repofiles.CreateOrUpdateRepoFile(repo, doer, opts)

		// asserts
		assert.Nil(t, err)
		gitRepo, _ := git.OpenRepository(repo.RepoPath())
		commitID, _ := gitRepo.GetBranchCommitID(opts.NewBranch)
		expectedFileResponse := getExpectedFileResponseForRepofilesCreate(commitID)
		assert.EqualValues(t, expectedFileResponse.Content, fileResponse.Content)
		assert.EqualValues(t, expectedFileResponse.Commit.SHA, fileResponse.Commit.SHA)
		assert.EqualValues(t, expectedFileResponse.Commit.HTMLURL, fileResponse.Commit.HTMLURL)
		assert.EqualValues(t, expectedFileResponse.Commit.Author.Email, fileResponse.Commit.Author.Email)
		assert.EqualValues(t, expectedFileResponse.Commit.Author.Name, fileResponse.Commit.Author.Name)
	})
}

func TestCreateOrUpdateRepoFileForUpdate(t *testing.T) {
	// setup
	onGiteaRun(t, func(t *testing.T, u *url.URL) {
		ctx := test.MockContext(t, "user2/repo1")
		ctx.SetParams(":id", "1")
		test.LoadRepo(t, ctx, 1)
		test.LoadRepoCommit(t, ctx)
		test.LoadUser(t, ctx, 2)
		test.LoadGitRepo(t, ctx)
		repo := ctx.Repo.Repository
		doer := ctx.User
		opts := getUpdateRepoFileOptions(repo)

		// test
		fileResponse, err := repofiles.CreateOrUpdateRepoFile(repo, doer, opts)

		// asserts
		assert.Nil(t, err)
		gitRepo, _ := git.OpenRepository(repo.RepoPath())
		commitID, _ := gitRepo.GetBranchCommitID(opts.NewBranch)
		expectedFileResponse := getExpectedFileResponseForRepofilesUpdate(commitID)
		assert.EqualValues(t, expectedFileResponse.Content, fileResponse.Content)
		assert.EqualValues(t, expectedFileResponse.Commit.SHA, fileResponse.Commit.SHA)
		assert.EqualValues(t, expectedFileResponse.Commit.HTMLURL, fileResponse.Commit.HTMLURL)
		assert.EqualValues(t, expectedFileResponse.Commit.Author.Email, fileResponse.Commit.Author.Email)
		assert.EqualValues(t, expectedFileResponse.Commit.Author.Name, fileResponse.Commit.Author.Name)
	})
}

func TestCreateOrUpdateRepoFileForUpdateWithFileMove(t *testing.T) {
	// setup
	onGiteaRun(t, func(t *testing.T, u *url.URL) {
		ctx := test.MockContext(t, "user2/repo1")
		ctx.SetParams(":id", "1")
		test.LoadRepo(t, ctx, 1)
		test.LoadRepoCommit(t, ctx)
		test.LoadUser(t, ctx, 2)
		test.LoadGitRepo(t, ctx)
		repo := ctx.Repo.Repository
		doer := ctx.User
		opts := getUpdateRepoFileOptions(repo)
		suffix := "_new"
		opts.FromTreePath = "README.md"
		opts.TreePath = "README.md" + suffix // new file name, README.md_new

		// test
		fileResponse, err := repofiles.CreateOrUpdateRepoFile(repo, doer, opts)

		// asserts
		assert.Nil(t, err)
		gitRepo, _ := git.OpenRepository(repo.RepoPath())
		commit, _ := gitRepo.GetBranchCommit(opts.NewBranch)
		expectedFileResponse := getExpectedFileResponseForRepofilesUpdate(commit.ID.String())
		// assert that the old file no longer exists in the last commit of the branch
		fromEntry, err := commit.GetTreeEntryByPath(opts.FromTreePath)
		toEntry, err := commit.GetTreeEntryByPath(opts.TreePath)
		assert.Nil(t, fromEntry)  // Should no longer exist here
		assert.NotNil(t, toEntry) // Should exist here
		// assert SHA has remained the same but paths use the new file name
		assert.EqualValues(t, expectedFileResponse.Content.SHA, fileResponse.Content.SHA)
		assert.EqualValues(t, expectedFileResponse.Content.Name+suffix, fileResponse.Content.Name)
		assert.EqualValues(t, expectedFileResponse.Content.Path+suffix, fileResponse.Content.Path)
		assert.EqualValues(t, expectedFileResponse.Content.URL+suffix, fileResponse.Content.URL)
		assert.EqualValues(t, expectedFileResponse.Commit.SHA, fileResponse.Commit.SHA)
		assert.EqualValues(t, expectedFileResponse.Commit.HTMLURL, fileResponse.Commit.HTMLURL)
	})
}

// Test opts with branch names removed, should get same results as above test
func TestCreateOrUpdateRepoFileWithoutBranchNames(t *testing.T) {
	// setup
	onGiteaRun(t, func(t *testing.T, u *url.URL) {
		ctx := test.MockContext(t, "user2/repo1")
		ctx.SetParams(":id", "1")
		test.LoadRepo(t, ctx, 1)
		test.LoadRepoCommit(t, ctx)
		test.LoadUser(t, ctx, 2)
		test.LoadGitRepo(t, ctx)
		repo := ctx.Repo.Repository
		doer := ctx.User
		opts := getUpdateRepoFileOptions(repo)
		opts.OldBranch = ""
		opts.NewBranch = ""

		// test
		fileResponse, err := repofiles.CreateOrUpdateRepoFile(repo, doer, opts)

		// asserts
		assert.Nil(t, err)
		gitRepo, _ := git.OpenRepository(repo.RepoPath())
		commitID, _ := gitRepo.GetBranchCommitID(repo.DefaultBranch)
		expectedFileResponse := getExpectedFileResponseForRepofilesUpdate(commitID)
		assert.EqualValues(t, expectedFileResponse.Content, fileResponse.Content)
	})
}

func TestCreateOrUpdateRepoFileErrors(t *testing.T) {
	// setup
	onGiteaRun(t, func(t *testing.T, u *url.URL) {
		ctx := test.MockContext(t, "user2/repo1")
		ctx.SetParams(":id", "1")
		test.LoadRepo(t, ctx, 1)
		test.LoadRepoCommit(t, ctx)
		test.LoadUser(t, ctx, 2)
		test.LoadGitRepo(t, ctx)
		repo := ctx.Repo.Repository
		doer := ctx.User

		t.Run("bad branch", func(t *testing.T) {
			opts := getUpdateRepoFileOptions(repo)
			opts.OldBranch = "bad_branch"
			fileResponse, err := repofiles.CreateOrUpdateRepoFile(repo, doer, opts)
			assert.Error(t, err)
			assert.Nil(t, fileResponse)
			expectedError := "branch does not exist [name: " + opts.OldBranch + "]"
			assert.EqualError(t, err, expectedError)
		})

		t.Run("bad SHA", func(t *testing.T) {
			opts := getUpdateRepoFileOptions(repo)
			origSHA := opts.SHA
			opts.SHA = "bad_sha"
			fileResponse, err := repofiles.CreateOrUpdateRepoFile(repo, doer, opts)
			assert.Nil(t, fileResponse)
			assert.Error(t, err)
			expectedError := "sha does not match [given: " + opts.SHA + ", expected: " + origSHA + "]"
			assert.EqualError(t, err, expectedError)
		})

		t.Run("new branch already exists", func(t *testing.T) {
			opts := getUpdateRepoFileOptions(repo)
			opts.NewBranch = "develop"
			fileResponse, err := repofiles.CreateOrUpdateRepoFile(repo, doer, opts)
			assert.Nil(t, fileResponse)
			assert.Error(t, err)
			expectedError := "branch already exists [name: " + opts.NewBranch + "]"
			assert.EqualError(t, err, expectedError)
		})

		t.Run("treePath is empty:", func(t *testing.T) {
			opts := getUpdateRepoFileOptions(repo)
			opts.TreePath = ""
			fileResponse, err := repofiles.CreateOrUpdateRepoFile(repo, doer, opts)
			assert.Nil(t, fileResponse)
			assert.Error(t, err)
			expectedError := "path contains a malformed path component [path: ]"
			assert.EqualError(t, err, expectedError)
		})

		t.Run("treePath is a git directory:", func(t *testing.T) {
			opts := getUpdateRepoFileOptions(repo)
			opts.TreePath = ".git"
			fileResponse, err := repofiles.CreateOrUpdateRepoFile(repo, doer, opts)
			assert.Nil(t, fileResponse)
			assert.Error(t, err)
			expectedError := "path contains a malformed path component [path: " + opts.TreePath + "]"
			assert.EqualError(t, err, expectedError)
		})

		t.Run("create file that already exists", func(t *testing.T) {
			opts := getCreateRepoFileOptions(repo)
			opts.TreePath = "README.md" //already exists
			fileResponse, err := repofiles.CreateOrUpdateRepoFile(repo, doer, opts)
			assert.Nil(t, fileResponse)
			assert.Error(t, err)
			expectedError := "repository file already exists [path: " + opts.TreePath + "]"
			assert.EqualError(t, err, expectedError)
		})
	})
}
