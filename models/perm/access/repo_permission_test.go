// Copyright 2024 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package access

import (
	"testing"

	perm_model "code.gitea.io/gitea/models/perm"
	repo_model "code.gitea.io/gitea/models/repo"
	"code.gitea.io/gitea/models/unit"
	user_model "code.gitea.io/gitea/models/user"

	"github.com/stretchr/testify/assert"
)

func TestApplyDefaultUserRepoPermission(t *testing.T) {
	perm := Permission{
		AccessMode: perm_model.AccessModeNone,
		UnitsMode:  map[unit.Type]perm_model.AccessMode{},
		Units: []*repo_model.RepoUnit{
			{Type: unit.TypeWiki, EveryoneAccessMode: perm_model.AccessModeNone},
		},
	}
	applyDefaultUserRepoPermission(nil, &perm)
	assert.False(t, perm.CanRead(unit.TypeWiki))

	perm = Permission{
		AccessMode: perm_model.AccessModeNone,
		UnitsMode:  map[unit.Type]perm_model.AccessMode{},
		Units: []*repo_model.RepoUnit{
			{Type: unit.TypeWiki, EveryoneAccessMode: perm_model.AccessModeRead},
		},
	}
	applyDefaultUserRepoPermission(&user_model.User{ID: 1}, &perm)
	assert.True(t, perm.CanRead(unit.TypeWiki))
}

func TestUnitAccessMode(t *testing.T) {
	perm := Permission{
		AccessMode: perm_model.AccessModeNone,
	}
	assert.Equal(t, perm_model.AccessModeNone, perm.UnitAccessMode(unit.TypeWiki), "no unit or map, use AccessMode")

	perm = Permission{
		AccessMode: perm_model.AccessModeOwner,
		Units: []*repo_model.RepoUnit{
			{Type: unit.TypeWiki, EveryoneAccessMode: perm_model.AccessModeRead},
		},
		UnitsMode: map[unit.Type]perm_model.AccessMode{},
	}
	assert.Equal(t, perm_model.AccessModeOwner, perm.UnitAccessMode(unit.TypeWiki), "only unit no map, use AccessMode")

	perm = Permission{
		AccessMode: perm_model.AccessModeAdmin,
		UnitsMode: map[unit.Type]perm_model.AccessMode{
			unit.TypeWiki: perm_model.AccessModeRead,
		},
	}
	assert.Equal(t, perm_model.AccessModeAdmin, perm.UnitAccessMode(unit.TypeWiki), "no unit only map, admin overrides map")

	perm = Permission{
		AccessMode: perm_model.AccessModeNone,
		UnitsMode: map[unit.Type]perm_model.AccessMode{
			unit.TypeWiki: perm_model.AccessModeRead,
		},
	}
	assert.Equal(t, perm_model.AccessModeRead, perm.UnitAccessMode(unit.TypeWiki), "no unit only map, use map")

	perm = Permission{
		AccessMode: perm_model.AccessModeNone,
		Units: []*repo_model.RepoUnit{
			{Type: unit.TypeWiki, EveryoneAccessMode: perm_model.AccessModeWrite},
		},
		UnitsMode: map[unit.Type]perm_model.AccessMode{
			unit.TypeWiki: perm_model.AccessModeRead,
		},
	}
	assert.Equal(t, perm_model.AccessModeRead, perm.UnitAccessMode(unit.TypeWiki), "has unit and map, use map")
}
