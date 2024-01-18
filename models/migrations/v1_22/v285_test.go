// Copyright 2023 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package v1_22 //nolint

import (
	"testing"

	"code.gitea.io/gitea/models/migrations/base"
	"xorm.io/xorm"

	"github.com/stretchr/testify/assert"
)

func PrepareOldRepository(t *testing.T) (*xorm.Engine, func()) {
	type Repository struct { // old struct
		ID int64 `xorm:"pk autoincr"`
	}

	// Prepare and load the testing database
	return base.PrepareTestEnv(t, 0, new(Repository))
}

func Test_RepositoryFormat(t *testing.T) {
	x, deferable := PrepareOldRepository(t)
	defer deferable()

	type Repository struct {
		ID               int64  `xorm:"pk autoincr"`
		ObjectFormatName string `xorg:"not null default('sha1')"`
	}

	repo := new(Repository)

	assert.NoError(t, AddObjectFormatNameToRepository(x))

	repo.ID = 20
	repo.ObjectFormatName = "sha256"
	_, err := x.Insert(repo)
	assert.NoError(t, err)

	repo = new(Repository)
	ok, err := x.ID(2).Get(repo)
	assert.NoError(t, err)
	assert.EqualValues(t, true, ok)
	assert.EqualValues(t, "sha1", repo.ObjectFormatName)

	repo = new(Repository)
	ok, err = x.ID(20).Get(repo)
	assert.NoError(t, err)
	assert.EqualValues(t, true, ok)
	assert.EqualValues(t, "sha256", repo.ObjectFormatName)
}
