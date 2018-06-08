// Copyright 2018 The Gitea Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package migrations

import (
	"fmt"

	"github.com/go-xorm/xorm"
)

func addVisibilityForUserAndOrg(x *xorm.Engine) error {
	type User struct {
		Visibility int `xorm:"NOT NULL DEFAULT 1"`
	}

	if err := x.Sync2(new(PublicKey)); err != nil {
		return fmt.Errorf("Sync2: %v", err)
	}
	return nil
}
