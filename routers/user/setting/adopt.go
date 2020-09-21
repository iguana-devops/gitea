// Copyright 2020 The Gitea Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package setting

import (
	"path/filepath"

	"code.gitea.io/gitea/models"
	"code.gitea.io/gitea/modules/context"
	"code.gitea.io/gitea/modules/repository"
	"code.gitea.io/gitea/modules/setting"
	"github.com/unknwon/com"
)

// AdoptOrDeleteRepository adopts or deletes a repository
func AdoptOrDeleteRepository(ctx *context.Context) {
	ctx.Data["Title"] = ctx.Tr("settings")
	ctx.Data["PageIsSettingsRepos"] = true
	allowAdopt := ctx.IsUserSiteAdmin() || setting.Repository.AllowAdoptionOfUnadoptedRepositories
	ctx.Data["allowAdopt"] = allowAdopt
	allowDelete := ctx.IsUserSiteAdmin() || setting.Repository.AllowDeleteOfUnadoptedRepositories
	ctx.Data["allowDelete"] = allowDelete

	dir := ctx.Query("name")
	action := ctx.Query("action")

	ctxUser := ctx.User
	root := filepath.Join(models.UserPath(ctxUser.LowerName))

	// check not a repo
	if has, err := models.IsRepositoryExist(ctxUser, dir); err != nil {
		ctx.ServerError("IsRepositoryExist", err)
		return
	} else if has || !com.IsDir(filepath.Join(root, dir+".git")) {
		// Fallthrough to failure mode
	} else if action == "adopt" && allowAdopt {
		if _, err := repository.AdoptRepository(ctxUser, ctxUser, models.CreateRepoOptions{
			Name:      dir,
			IsPrivate: true,
		}); err != nil {
			ctx.ServerError("repository.AdoptRepository", err)
			return
		}
	} else if action == "delete" && allowDelete {
		if err := repository.DeleteUnadoptedRepository(ctxUser, ctxUser, dir); err != nil {
			ctx.ServerError("repository.AdoptRepository", err)
			return
		}
	}

	ctx.Redirect(setting.AppSubURL + "/user/settings/repos")
}
