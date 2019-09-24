// Copyright 2019 The Gitea Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package migrations

import (
	"strings"

	"github.com/go-xorm/xorm"
)

func updateMigrationServiceTypes(x *xorm.Engine) error {
	for {
		sql := "SELECT id, original_url FROM WHERE original_url <> '' LIMIT 50 ORDER BY id"
		var results = make([]struct {
			ID          int64
			OriginalURL string
		}, 0, 50)
		err := x.SQL(sql).Find(results)
		if err != nil {
			return err
		}
		if len(results) == 0 {
			return nil
		}

		const PlainGitService = 1 // 1 plain git service
		const GithubService = 2   // 2 github.com

		for _, res := range results {
			u := strings.ToLower(res.OriginalURL)
			var serviceType = PlainGitService
			if strings.HasPrefix(u, "https://github.com") || strings.HasPrefix(u, "http://github.com") {
				serviceType = GithubService
			}
			_, err = x.Exec("UPDATE repository SET original_service_type = ? WHERE id = ?", serviceType, res.ID)
			if err != nil {
				return err
			}
		}
	}
}
