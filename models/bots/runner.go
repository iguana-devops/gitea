// Copyright 2021 The Gitea Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package bots

import (
	"context"
	"fmt"

	"code.gitea.io/gitea/models/db"
	repo_model "code.gitea.io/gitea/models/repo"
	user_model "code.gitea.io/gitea/models/user"
	"code.gitea.io/gitea/modules/timeutil"

	"xorm.io/builder"
)

// ErrRunnerNotExist represents an error for bot runner not exist
type ErrRunnerNotExist struct {
	UUID  string
	Token string
}

func (err ErrRunnerNotExist) Error() string {
	if err.UUID != "" {
		return fmt.Sprintf("Bot runner ID [%s] is not exist", err.UUID)
	}

	return fmt.Sprintf("Bot runner token [%s] is not exist", err.Token)
}

// Runner represents runner machines
type Runner struct {
	ID          int64
	UUID        string                 `xorm:"CHAR(36) UNIQUE"`
	Name        string                 `xorm:"VARCHAR(32) UNIQUE"`
	OS          string                 `xorm:"VARCHAR(16) index"` // the runner running os
	Arch        string                 `xorm:"VARCHAR(16) index"` // the runner running architecture
	Type        string                 `xorm:"VARCHAR(16)"`
	OwnerID     int64                  `xorm:"index"` // org level runner, 0 means system
	Owner       *user_model.User       `xorm:"-"`
	RepoID      int64                  `xorm:"index"` // repo level runner, if orgid also is zero, then it's a global
	Repo        *repo_model.Repository `xorm:"-"`
	Description string                 `xorm:"TEXT"`
	Base        int                    // 0 native 1 docker 2 virtual machine
	RepoRange   string                 // glob match which repositories could use this runner
	Token       string
	Capacity    int64
	LastOnline  timeutil.TimeStamp `xorm:"index"`
	Created     timeutil.TimeStamp `xorm:"created"`
}

func (Runner) TableName() string {
	return "bots_runner"
}

func (r *Runner) OwnType() string {
	if r.OwnerID == 0 {
		return "Global Type"
	}
	if r.RepoID == 0 {
		return r.Owner.Name
	}

	return r.Repo.FullName()
}

func init() {
	db.RegisterModel(&Runner{})
}

type FindRunnerOptions struct {
	db.ListOptions
	RepoID  int64
	OwnerID int64
}

func (opts FindRunnerOptions) toCond() builder.Cond {
	cond := builder.NewCond()
	if opts.RepoID > 0 {
		cond = cond.And(builder.Eq{"repo_id": opts.RepoID})
	}
	if opts.OwnerID > 0 {
		cond = cond.And(builder.Eq{"owner_id": opts.OwnerID})
	}
	cond = cond.Or(builder.Eq{"repo_id": 0, "owner_id": 0})
	return cond
}

func CountRunners(opts FindRunnerOptions) (int64, error) {
	return db.GetEngine(db.DefaultContext).
		Table("bots_runner").
		Where(opts.toCond()).
		Count()
}

func FindRunners(opts FindRunnerOptions) (runners RunnerList, err error) {
	sess := db.GetEngine(db.DefaultContext).
		Where(opts.toCond())
	if opts.Page > 0 {
		sess.Limit(opts.PageSize, (opts.Page-1)*opts.PageSize)
	}
	return runners, sess.Find(&runners)
}

// GetUsableRunner returns the usable runner
func GetUsableRunner(opts FindRunnerOptions) (*Runner, error) {
	var runner Runner
	has, err := db.GetEngine(db.DefaultContext).
		Where(opts.toCond()).
		Asc("last_online").
		Get(&runner)
	if err != nil {
		return nil, err
	}
	if !has {
		return nil, ErrRunnerNotExist{}
	}

	return &runner, nil
}

// GetRunnerByUUID returns a bot runner via uuid
func GetRunnerByUUID(uuid string) (*Runner, error) {
	var runner Runner
	has, err := db.GetEngine(db.DefaultContext).Where("uuid=?", uuid).Get(&runner)
	if err != nil {
		return nil, err
	} else if !has {
		return nil, ErrRunnerNotExist{
			UUID: uuid,
		}
	}
	return &runner, nil
}

// GetRunnerByToken returns a bot runner via token
func GetRunnerByToken(token string) (*Runner, error) {
	var runner Runner
	has, err := db.GetEngine(db.DefaultContext).Where("token=?", token).Get(&runner)
	if err != nil {
		return nil, err
	} else if !has {
		return nil, ErrRunnerNotExist{
			UUID: "",
		}
	}
	return &runner, nil
}

// UpdateRunner updates runner's information.
func UpdateRunner(ctx context.Context, r *Runner, cols ...string) (err error) {
	e := db.GetEngine(ctx)

	if len(cols) == 0 {
		_, err = e.ID(r.ID).AllCols().Update(r)
	} else {
		_, err = e.ID(r.ID).Cols(cols...).Update(r)
	}
	return err
}

// FindRunnersByRepoID returns all workers for the repository
func FindRunnersByRepoID(repoID int64) ([]*Runner, error) {
	var runners []*Runner
	err := db.GetEngine(db.DefaultContext).Where("repo_id=? OR repo_id=0", repoID).
		Find(&runners)
	if err != nil {
		return nil, err
	}
	err = db.GetEngine(db.DefaultContext).Join("INNER", "repository", "repository.owner_id = bot_runner.owner_id").Find(&runners)
	return runners, err
}
