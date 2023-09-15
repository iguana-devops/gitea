// Copyright 2019 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package setting

import (
	"errors"
	"fmt"
	"net/http"

	"code.gitea.io/gitea/models/auth"
	user_model "code.gitea.io/gitea/models/user"
	"code.gitea.io/gitea/modules/base"
	"code.gitea.io/gitea/modules/context"
	"code.gitea.io/gitea/modules/util"
	"code.gitea.io/gitea/modules/web"
	shared_user "code.gitea.io/gitea/routers/web/shared/user"
	"code.gitea.io/gitea/services/audit"
	"code.gitea.io/gitea/services/forms"
)

type OAuth2CommonHandlers struct {
	Doer               *user_model.User
	Owner              *user_model.User // nil for instance-wide, otherwise Org or User
	BasePathList       string           // the base URL for the application list page, eg: "/user/setting/applications"
	BasePathEditPrefix string           // the base URL for the application edit page, will be appended with app id, eg: "/user/setting/applications/oauth2"
	TplAppEdit         base.TplName     // the template for the application edit page
}

func (oa *OAuth2CommonHandlers) ownerID() int64 {
	if oa.Owner != nil {
		return oa.Owner.ID
	}
	return 0
}

func (oa *OAuth2CommonHandlers) auditActionSwitch(user, org, system audit.Action) audit.Action {
	if oa.Owner == nil {
		return system
	}
	if oa.Owner.IsOrganization() {
		return org
	}
	return user
}

func (oa *OAuth2CommonHandlers) renderEditPage(ctx *context.Context) {
	app := ctx.Data["App"].(*auth.OAuth2Application)
	ctx.Data["FormActionPath"] = fmt.Sprintf("%s/%d", oa.BasePathEditPrefix, app.ID)

	if ctx.ContextUser.IsOrganization() {
		err := shared_user.LoadHeaderCount(ctx)
		if err != nil {
			ctx.ServerError("LoadHeaderCount", err)
			return
		}
	}

	ctx.HTML(http.StatusOK, oa.TplAppEdit)
}

// AddApp adds an oauth2 application
func (oa *OAuth2CommonHandlers) AddApp(ctx *context.Context) {
	form := web.GetForm(ctx).(*forms.EditOAuth2ApplicationForm)
	if ctx.HasError() {
		ctx.Flash.Error(ctx.GetErrMsg())
		// go to the application list page
		ctx.Redirect(oa.BasePathList)
		return
	}

	// TODO validate redirect URI
	app, err := auth.CreateOAuth2Application(ctx, auth.CreateOAuth2ApplicationOptions{
		Name:               form.Name,
		RedirectURIs:       util.SplitTrimSpace(form.RedirectURIs, "\n"),
		UserID:             oa.ownerID(),
		ConfidentialClient: form.ConfidentialClient,
	})
	if err != nil {
		ctx.ServerError("CreateOAuth2Application", err)
		return
	}

	audit.Record(oa.auditActionSwitch(audit.UserOAuth2ApplicationAdd, audit.OrganizationOAuth2ApplicationAdd, audit.SystemOAuth2ApplicationAdd), oa.Doer, oa.Owner, app, "Created OAuth2 application %s.", app.Name)

	// render the edit page with secret
	ctx.Flash.Success(ctx.Tr("settings.create_oauth2_application_success"), true)
	ctx.Data["App"] = app
	ctx.Data["ClientSecret"], err = app.GenerateClientSecret()
	if err != nil {
		ctx.ServerError("GenerateClientSecret", err)
		return
	}
	oa.renderEditPage(ctx)
}

// EditShow displays the given application
func (oa *OAuth2CommonHandlers) EditShow(ctx *context.Context) {
	app, err := auth.GetOAuth2ApplicationByID(ctx, ctx.ParamsInt64("id"))
	if err != nil {
		if auth.IsErrOAuthApplicationNotFound(err) {
			ctx.NotFound("Application not found", err)
			return
		}
		ctx.ServerError("GetOAuth2ApplicationByID", err)
		return
	}
	if app.UID != oa.ownerID() {
		ctx.NotFound("Application not found", nil)
		return
	}
	ctx.Data["App"] = app
	oa.renderEditPage(ctx)
}

// EditSave saves the oauth2 application
func (oa *OAuth2CommonHandlers) EditSave(ctx *context.Context) {
	form := web.GetForm(ctx).(*forms.EditOAuth2ApplicationForm)

	if ctx.HasError() {
		oa.renderEditPage(ctx)
		return
	}

	// TODO validate redirect URI
	app, err := auth.UpdateOAuth2Application(auth.UpdateOAuth2ApplicationOptions{
		ID:                 ctx.ParamsInt64("id"),
		Name:               form.Name,
		RedirectURIs:       util.SplitTrimSpace(form.RedirectURIs, "\n"),
		UserID:             oa.ownerID(),
		ConfidentialClient: form.ConfidentialClient,
	})
	if err != nil {
		ctx.ServerError("UpdateOAuth2Application", err)
		return
	}

	ctx.Data["App"] = app

	audit.Record(oa.auditActionSwitch(audit.UserOAuth2ApplicationUpdate, audit.OrganizationOAuth2ApplicationUpdate, audit.SystemOAuth2ApplicationUpdate), oa.Doer, oa.Owner, app, "Updated OAuth2 application %s.", app.Name)

	ctx.Flash.Success(ctx.Tr("settings.update_oauth2_application_success"))
	ctx.Redirect(oa.BasePathList)
}

// RegenerateSecret regenerates the secret
func (oa *OAuth2CommonHandlers) RegenerateSecret(ctx *context.Context) {
	app, err := auth.GetOAuth2ApplicationByID(ctx, ctx.ParamsInt64("id"))
	if err != nil {
		if auth.IsErrOAuthApplicationNotFound(err) {
			ctx.NotFound("Application not found", err)
			return
		}
		ctx.ServerError("GetOAuth2ApplicationByID", err)
		return
	}
	if app.UID != oa.ownerID() {
		ctx.NotFound("Application not found", nil)
		return
	}
	ctx.Data["App"] = app
	ctx.Data["ClientSecret"], err = app.GenerateClientSecret()
	if err != nil {
		ctx.ServerError("GenerateClientSecret", err)
		return
	}

	audit.Record(oa.auditActionSwitch(audit.UserOAuth2ApplicationSecret, audit.OrganizationOAuth2ApplicationSecret, audit.SystemOAuth2ApplicationSecret), oa.Doer, oa.Owner, app, "Regenerated secret for OAuth2 application %s.", app.Name)

	ctx.Flash.Success(ctx.Tr("settings.update_oauth2_application_success"), true)
	oa.renderEditPage(ctx)
}

// DeleteApp deletes the given oauth2 application
func (oa *OAuth2CommonHandlers) DeleteApp(ctx *context.Context) {
	app, err := auth.GetOAuth2ApplicationByID(ctx, ctx.ParamsInt64("id"))
	if err != nil {
		if errors.Is(err, util.ErrNotExist) {
			ctx.NotFound("Application not found", err)
		} else {
			ctx.ServerError("GetOAuth2ApplicationByID", err)
		}
		return
	}

	if err := auth.DeleteOAuth2Application(app.ID, oa.ownerID()); err != nil {
		ctx.ServerError("DeleteOAuth2Application", err)
		return
	}

	audit.Record(oa.auditActionSwitch(audit.UserOAuth2ApplicationRemove, audit.OrganizationOAuth2ApplicationRemove, audit.SystemOAuth2ApplicationRemove), oa.Doer, oa.Owner, app, "Removed OAuth2 application %s.", app.Name)

	ctx.Flash.Success(ctx.Tr("settings.remove_oauth2_application_success"))
	ctx.JSONRedirect(oa.BasePathList)
}

// RevokeGrant revokes the grant
func (oa *OAuth2CommonHandlers) RevokeGrant(ctx *context.Context) {
	grant, err := auth.GetOAuth2GrantByID(ctx, ctx.ParamsInt64("grantId"))
	if err != nil {
		ctx.ServerError("GetOAuth2GrantByID", err)
		return
	}
	if grant == nil {
		ctx.NotFound("Grant not found", nil)
		return
	}

	app, err := auth.GetOAuth2ApplicationByID(ctx, grant.ApplicationID)
	if err != nil {
		if errors.Is(err, util.ErrNotExist) {
			ctx.NotFound("Application not found", err)
		} else {
			ctx.ServerError("GetOAuth2ApplicationByID", err)
		}
		return
	}

	if err := auth.RevokeOAuth2Grant(ctx, grant.ID, oa.ownerID()); err != nil {
		ctx.ServerError("RevokeOAuth2Grant", err)
		return
	}

	audit.Record(audit.UserOAuth2ApplicationRevoke, oa.Doer, oa.Owner, grant, "Revoked OAuth2 grant for application %s.", app.Name)

	ctx.Flash.Success(ctx.Tr("settings.revoke_oauth2_grant_success"))
	ctx.JSONRedirect(oa.BasePathList)
}
