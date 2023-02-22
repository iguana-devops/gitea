// Copyright 2019 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package cmd

import (
	"fmt"

	"code.gitea.io/gitea/models/db"
	"code.gitea.io/gitea/modules/log"
	"code.gitea.io/gitea/modules/setting"

	"github.com/urfave/cli"
)

// CmdConvert represents the available convert sub-command.
var CmdConvert = cli.Command{
	Name:        "convert",
	Usage:       "Convert the database",
	Description: "A command to convert an existing MySQL database from utf8 to utf8mb4",
	Action:      runConvert,
}

func runConvert(ctx *cli.Context) error {
	stdCtx, cancel := installSignals()
	defer cancel()

	if err := initDB(stdCtx); err != nil {
		return err
	}

	log.Info("AppPath: %s", setting.AppPath)
	log.Info("AppWorkPath: %s", setting.AppWorkPath)
	log.Info("Custom path: %s", setting.CustomPath)
	log.Info("Log path: %s", setting.Log.RootPath)
	log.Info("Configuration file: %s", setting.CustomConf)

	if !setting.Database.UseMySQL {
		fmt.Println("This command can only be used with a MySQL database")
		return nil
	}

	if err := db.ConvertUtf8ToUtf8mb4(); err != nil {
		log.Fatal("Failed to convert database from utf8 to utf8mb4: %w", err)
		return err
	}

	fmt.Println("Converted successfully, please confirm your database's character set is now utf8mb4")

	return nil
}
