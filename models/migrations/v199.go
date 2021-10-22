// Copyright 2021 The Gitea Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package migrations

import (
	"xorm.io/xorm"
)

func addRemoteVersionTableNoop(x *xorm.Engine) error {
	// we used to use a table `remote_version` to store information for updater, now we use `AppState`, so this migration task is a no-op now.
	return nil
}
