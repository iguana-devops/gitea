// Copyright 2021 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package actions

import (
	"context"
	"fmt"
	"strings"
	"time"

	"code.gitea.io/gitea/models/db"
	"code.gitea.io/gitea/models/organization"
	repo_model "code.gitea.io/gitea/models/repo"
	"code.gitea.io/gitea/models/shared/types"
	user_model "code.gitea.io/gitea/models/user"
	"code.gitea.io/gitea/modules/timeutil"
	"code.gitea.io/gitea/modules/translation"
	"code.gitea.io/gitea/modules/util"

	runnerv1 "code.gitea.io/actions-proto-go/runner/v1"
	"xorm.io/builder"
)

// ActionRunner represents runner machines
type ActionRunner struct {
	ID          int64
	UUID        string                 `xorm:"CHAR(36) UNIQUE"`
	Name        string                 `xorm:"VARCHAR(255)"`
	Version     string                 `xorm:"VARCHAR(64)"`
	OwnerID     int64                  `xorm:"index"` // org level runner, 0 means system
	Owner       *user_model.User       `xorm:"-"`
	RepoID      int64                  `xorm:"index"` // repo level runner, if OwnerID also is zero, then it's a global
	Repo        *repo_model.Repository `xorm:"-"`
	Description string                 `xorm:"TEXT"`
	Base        int                    // 0 native 1 docker 2 virtual machine
	RepoRange   string                 // glob match which repositories could use this runner

	Token     string `xorm:"-"`
	TokenHash string `xorm:"UNIQUE"` // sha256 of token
	TokenSalt string
	// TokenLastEight string `xorm:"token_last_eight"` // it's unnecessary because we don't find runners by token

	LastOnline timeutil.TimeStamp `xorm:"index"`
	LastActive timeutil.TimeStamp `xorm:"index"`

	// Store labels defined in state file (default: .runner file) of `act_runner`
	AgentLabels []string `xorm:"TEXT"`

	Created timeutil.TimeStamp `xorm:"created"`
	Updated timeutil.TimeStamp `xorm:"updated"`
	Deleted timeutil.TimeStamp `xorm:"deleted"`
}

const (
	RunnerOfflineTime = time.Minute
	RunnerIdleTime    = 10 * time.Second
)

// BelongsToOwnerName before calling, should guarantee that all attributes are loaded
func (r *ActionRunner) BelongsToOwnerName() string {
	if r.RepoID != 0 {
		return r.Repo.FullName()
	}
	if r.OwnerID != 0 {
		return r.Owner.Name
	}
	return ""
}

func (r *ActionRunner) BelongsToOwnerType() types.OwnerType {
	if r.RepoID != 0 {
		return types.OwnerTypeRepository
	}
	if r.OwnerID != 0 {
		if r.Owner.Type == user_model.UserTypeOrganization {
			return types.OwnerTypeOrganization
		} else if r.Owner.Type == user_model.UserTypeIndividual {
			return types.OwnerTypeIndividual
		}
	}
	return types.OwnerTypeSystemGlobal
}

// if the logic here changed, you should also modify FindRunnerOptions.ToCond
func (r *ActionRunner) Status() runnerv1.RunnerStatus {
	if time.Since(r.LastOnline.AsTime()) > RunnerOfflineTime {
		return runnerv1.RunnerStatus_RUNNER_STATUS_OFFLINE
	}
	if time.Since(r.LastActive.AsTime()) > RunnerIdleTime {
		return runnerv1.RunnerStatus_RUNNER_STATUS_IDLE
	}
	return runnerv1.RunnerStatus_RUNNER_STATUS_ACTIVE
}

func (r *ActionRunner) StatusName() string {
	return strings.ToLower(strings.TrimPrefix(r.Status().String(), "RUNNER_STATUS_"))
}

func (r *ActionRunner) StatusLocaleName(lang translation.Locale) string {
	return lang.TrString("actions.runners.status." + r.StatusName())
}

func (r *ActionRunner) IsOnline() bool {
	status := r.Status()
	if status == runnerv1.RunnerStatus_RUNNER_STATUS_IDLE || status == runnerv1.RunnerStatus_RUNNER_STATUS_ACTIVE {
		return true
	}
	return false
}

// EditLink returns edit runner link
// Should ensure attributes are loaded before call this function
func (r *ActionRunner) EditLink(admin bool) string {
	if admin {
		return fmt.Sprintf("/admin/actions/runners/%d", r.ID)
	}

	switch r.BelongsToOwnerType() {
	case types.OwnerTypeSystemGlobal:
		return fmt.Sprintf("/admin/actions/runners/%d", r.ID)
	case types.OwnerTypeIndividual:
		return fmt.Sprintf("/user/settings/actions/runners/%d", r.ID)
	case types.OwnerTypeRepository:
		return fmt.Sprintf("%s/settings/actions/runners/%d", r.Repo.Link(), r.ID)
	case types.OwnerTypeOrganization:
		return fmt.Sprintf("%s/settings/actions/runners/%d", r.Owner.OrganisationLink(), r.ID)
	}
	return ""
}

// Editable checks if the runner is editable by the user
func (r *ActionRunner) Editable(ctx context.Context, doer, owner *user_model.User, repo *repo_model.Repository) (bool, error) {
	if doer == nil {
		return false, nil
	}

	// admin can edit all runners
	if doer.IsAdmin {
		return true, nil
	}

	switch r.BelongsToOwnerType() {
	case types.OwnerTypeIndividual:
		return owner != nil && r.Owner.ID == doer.ID, nil
	case types.OwnerTypeRepository:
		return repo != nil && r.RepoID == repo.ID, nil
	case types.OwnerTypeOrganization:
		if (repo != nil && r.OwnerID == repo.OwnerID) || (owner != nil && r.OwnerID == owner.ID) {
			isOrgAdmin, err := organization.IsOrganizationAdmin(ctx, r.OwnerID, doer.ID)
			if err != nil {
				return false, err
			}
			return isOrgAdmin, nil
		}
	}

	return false, nil
}

// LoadAttributes loads the attributes of the runner
func (r *ActionRunner) LoadAttributes(ctx context.Context) error {
	if r.OwnerID > 0 {
		var user user_model.User
		has, err := db.GetEngine(ctx).ID(r.OwnerID).Get(&user)
		if err != nil {
			return err
		}
		if has {
			r.Owner = &user
		}
	}
	if r.RepoID > 0 {
		var repo repo_model.Repository
		has, err := db.GetEngine(ctx).ID(r.RepoID).Get(&repo)
		if err != nil {
			return err
		}
		if has {
			r.Repo = &repo
		}
	}
	return nil
}

func (r *ActionRunner) GenerateToken() (err error) {
	r.Token, r.TokenSalt, r.TokenHash, _, err = generateSaltedToken()
	return err
}

func init() {
	db.RegisterModel(&ActionRunner{})
}

type FindRunnerOptions struct {
	db.ListOptions
	RepoID        int64
	Repo          *repo_model.Repository
	OwnerID       int64
	Owner         *user_model.User
	Sort          string
	Filter        string
	IsOnline      util.OptionalBool
	WithAvailable bool // not only runners belong to, but also runners can be used
}

func (opts FindRunnerOptions) ToConds() builder.Cond {
	cond := builder.NewCond()

	if opts.RepoID > 0 {
		c := builder.NewCond().And(builder.Eq{"repo_id": opts.RepoID})
		if opts.WithAvailable {
			c = c.Or(builder.Eq{"owner_id": builder.Select("owner_id").From("repository").Where(builder.Eq{"id": opts.RepoID})})
			c = c.Or(builder.Eq{"repo_id": 0, "owner_id": 0})
		}
		cond = cond.And(c)
	}
	if opts.OwnerID > 0 {
		c := builder.NewCond().And(builder.Eq{"owner_id": opts.OwnerID})
		if opts.WithAvailable {
			c = c.Or(builder.Eq{"repo_id": 0, "owner_id": 0})
		}
		cond = cond.And(c)
	}

	if opts.Filter != "" {
		cond = cond.And(builder.Like{"name", opts.Filter})
	}

	if opts.IsOnline.IsTrue() {
		cond = cond.And(builder.Gt{"last_online": time.Now().Add(-RunnerOfflineTime).Unix()})
	} else if opts.IsOnline.IsFalse() {
		cond = cond.And(builder.Lte{"last_online": time.Now().Add(-RunnerOfflineTime).Unix()})
	}
	return cond
}

func (opts FindRunnerOptions) ToOrders() string {
	switch opts.Sort {
	case "online":
		return "last_online DESC"
	case "offline":
		return "last_online ASC"
	case "alphabetically":
		return "name ASC"
	case "reversealphabetically":
		return "name DESC"
	case "newest":
		return "id DESC"
	case "oldest":
		return "id ASC"
	}
	return "last_online DESC"
}

// GetRunnerByUUID returns a runner via uuid
func GetRunnerByUUID(ctx context.Context, uuid string) (*ActionRunner, error) {
	var runner ActionRunner
	has, err := db.GetEngine(ctx).Where("uuid=?", uuid).Get(&runner)
	if err != nil {
		return nil, err
	} else if !has {
		return nil, fmt.Errorf("runner with uuid %s: %w", uuid, util.ErrNotExist)
	}
	return &runner, nil
}

// GetRunnerByID returns a runner via id
func GetRunnerByID(ctx context.Context, id int64) (*ActionRunner, error) {
	var runner ActionRunner
	has, err := db.GetEngine(ctx).Where("id=?", id).Get(&runner)
	if err != nil {
		return nil, err
	} else if !has {
		return nil, fmt.Errorf("runner with id %d: %w", id, util.ErrNotExist)
	}
	return &runner, nil
}

// UpdateRunner updates runner's information.
func UpdateRunner(ctx context.Context, r *ActionRunner, cols ...string) error {
	e := db.GetEngine(ctx)
	var err error
	if len(cols) == 0 {
		_, err = e.ID(r.ID).AllCols().Update(r)
	} else {
		_, err = e.ID(r.ID).Cols(cols...).Update(r)
	}
	return err
}

// DeleteRunner deletes a runner by given ID.
func DeleteRunner(ctx context.Context, id int64) error {
	if _, err := GetRunnerByID(ctx, id); err != nil {
		return err
	}

	_, err := db.DeleteByID[ActionRunner](ctx, id)
	return err
}

// CreateRunner creates new runner.
func CreateRunner(ctx context.Context, t *ActionRunner) error {
	return db.Insert(ctx, t)
}

func CountRunnersWithoutBelongingOwner(ctx context.Context) (int64, error) {
	// Only affect action runners were a owner ID is set, as actions runners
	// could also be created on a repository.
	return db.GetEngine(ctx).Table("action_runner").
		Join("LEFT", "user", "`action_runner`.owner_id = `user`.id").
		Where("`action_runner`.owner_id != ?", 0).
		And(builder.IsNull{"`user`.id"}).
		Count(new(ActionRunner))
}

func FixRunnersWithoutBelongingOwner(ctx context.Context) (int64, error) {
	subQuery := builder.Select("`action_runner`.id").
		From("`action_runner`").
		Join("LEFT", "user", "`action_runner`.owner_id = `user`.id").
		Where(builder.Neq{"`action_runner`.owner_id": 0}).
		And(builder.IsNull{"`user`.id"})
	b := builder.Delete(builder.In("id", subQuery)).From("`action_runner`")
	res, err := db.GetEngine(ctx).Exec(b)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
