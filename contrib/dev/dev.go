// Copyright 2023 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	_ "code.gitea.io/gitea/models"
	"code.gitea.io/gitea/models/db"
	"code.gitea.io/gitea/models/unittest"
	"code.gitea.io/gitea/modules/graceful"
	"code.gitea.io/gitea/modules/log"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/modules/util"
	"code.gitea.io/gitea/routers"
	"code.gitea.io/gitea/routers/common"
	"gopkg.in/yaml.v3"
)

// To start a gitea develop server with the test data, and auto update test data when the service stop.
// GITEA_ROOT=`pwd` go run -tags 'sqlite sqlite_unlock_notify' contrib/dev/dev.go

func main() {
	pwd := os.Getenv("GITEA_ROOT")
	if len(pwd) == 0 {
		panic(pwd)
	}
	log.Info("GITEA_ROOT: %s", pwd)

	defer log.GetManager().Close()

	managerCtx, cancel := context.WithCancel(context.Background())
	graceful.InitManager(managerCtx)
	defer cancel()

	initDev(pwd)

	// Set up Chi routes
	webRoutes := routers.NormalRoutes()
	err := runHTTP("tcp", ":3000", "Web", webRoutes, setting.UseProxyProtocol)
	if err != nil {
		log.Fatal("err: %#v", err)
	}

	<-graceful.GetManager().Done()
	log.Info("PID: %d Gitea Web Finished", os.Getpid())
	fixGitReops()

	ctxDb, cancel := context.WithCancel(context.Background())
	err = common.InitDBEngine(ctxDb)
	if err != nil {
		log.Fatal("common.InitDBEngine: %v", err)
	}
	err = unittest.DumpAllFixtures(filepath.Join(pwd, "models", "fixtures"))
	cancel()

	if err != nil {
		log.Fatal("unittest.DumpAllFixtures: %v", err)
	}
	removeNotNeededFixtures(pwd)
	recheckFixtures(pwd)

	log.GetManager().Close()
}

func buildInterfacesSlice(records interface{}) ([]interface{}, error) {
	switch records := records.(type) {
	case []interface{}:
		return records, nil
	case map[string]interface{}:
		var result []interface{}
		for _, record := range records {
			result = append(result, record)
		}
		return result, nil
	}

	return nil, fmt.Errorf("testfixtures: fixture is not a slice or map")
}

func recheckFixtures(pathToGiteaRoot string) {
	err := filepath.Walk(path.Join(pathToGiteaRoot, "models", "fixtures"), func(pth string, info fs.FileInfo, _ error) error {
		if info.IsDir() {
			return nil
		}

		fileName := path.Base(pth)
		if !strings.HasSuffix(fileName, ".yml") {
			return nil
		}

		log.Info("recheck %s", fileName)

		content, err := os.ReadFile(pth)
		if err != nil {
			return err
		}

		var records interface{}
		if err := yaml.Unmarshal(content, &records); err != nil {
			return fmt.Errorf("could not unmarshal YAML: %w", err)
		}

		result, err := buildInterfacesSlice(records)
		if err != nil {
			return err
		}

		for _, record := range result {
			_, ok := record.(map[string]interface{})
			if !ok {
				return fmt.Errorf("testfixtures: could not cast record: not a map[interface{}]interface{}")
			}
		}

		return nil
	})

	if err != nil {
		log.Fatal("recheckFixtures: %v", err)
	}
}

func listSubDir(dirname string, onDir func(path, name string) error) error {
	fileInfos, err := os.ReadDir(dirname)
	if err != nil {
		return err
	}

	for _, fi := range fileInfos {
		if !fi.IsDir() {
			continue
		}

		err = onDir(path.Join(dirname, fi.Name()), fi.Name())
		if err != nil {
			return err
		}
	}

	return nil
}

func fixGitReops() {
	type fixItem struct {
		Path    string
		Name    string
		Content string
	}

	allFixs := []fixItem{
		{
			Path: "hooks",
			Name: "update",
			Content: "#!/usr/bin/env bash\n" +
				"ORI_DIR=`pwd`\n" +
				"SHELL_FOLDER=$(cd \"$(dirname \"$0\")\";pwd)\n" +
				"cd \"$ORI_DIR\"\n" +
				"for i in `ls \"$SHELL_FOLDER/update.d\"`; do\n" +
				"    sh \"$SHELL_FOLDER/update.d/$i\" $1 $2 $3\n" +
				"done",
		},
		{
			Path: "hooks",
			Name: "pre-receive",
			Content: "#!/usr/bin/env bash\n" +
				"ORI_DIR=`pwd`\n" +
				"SHELL_FOLDER=$(cd \"$(dirname \"$0\")\";pwd)\n" +
				"cd \"$ORI_DIR\"\n" +
				"for i in `ls \"$SHELL_FOLDER/pre-receive.d\"`; do\n" +
				"    sh \"$SHELL_FOLDER/pre-receive.d/$i\"\n" +
				"done",
		},
		{
			Path: "hooks",
			Name: "post-receive",
			Content: "#!/usr/bin/env bash\n" +
				"ORI_DIR=`pwd`\n" +
				"SHELL_FOLDER=$(cd \"$(dirname \"$0\")\";pwd)\n" +
				"cd \"$ORI_DIR\"\n" +
				"for i in `ls \"$SHELL_FOLDER/post-receive.d\"`; do\n" +
				"    sh \"$SHELL_FOLDER/post-receive.d/$i\"\n" +
				"done",
		},
		{
			Path: path.Join("hooks", "update.d"),
			Name: "gitea",
			Content: `#!/usr/bin/env bash
"$GITEA_ROOT/gitea" hook --config="$GITEA_ROOT/$GITEA_CONF" update $1 $2 $3
`,
		},
		{
			Path: path.Join("hooks", "pre-receive.d"),
			Name: "gitea",
			Content: `#!/usr/bin/env bash
"$GITEA_ROOT/gitea" hook --config="$GITEA_ROOT/$GITEA_CONF" pre-receive
`,
		},
		{
			Path: path.Join("hooks", "post-receive.d"),
			Name: "gitea",
			Content: `#!/usr/bin/env bash
"$GITEA_ROOT/gitea" hook --config="$GITEA_ROOT/$GITEA_CONF" post-receive
`,
		},
	}

	neededReops := []string{
		"privated_org/private_repo_on_private_org.git",
		"privated_org/public_repo_on_private_org.git",
		"user3/repo5.git",
		"user3/repo3.git",
		"user13/repo11.git",
		"user27/template1.git",
		"user27/repo49.git",
		"org26/repo_external_tracker.git",
		"org26/repo_external_tracker_alpha.git",
		"org26/repo_external_tracker_numeric.git",
		"limited_org/public_repo_on_limited_org.git",
		"limited_org/private_repo_on_limited_org.git",
		"user5/repo4.git",
		"user2/readme-test.git",
		"user2/utf8.git",
		"user2/repo1.wiki.git",
		"user2/repo15.git",
		"user2/repo2.git",
		"user2/repo20.git",
		"user2/commitsonpr.git",
		"user2/repo1.git",
		"user2/glob.git",
		"user2/repo16.git",
		"user2/repo-release.git",
		"user2/lfs.git",
		"user2/git_hooks_test.git",
		"user2/commits_search_test.git",
		"user12/repo10.git",
		"migration/lfs-test.git",
		"user30/renderer.git",
		"user30/empty.git",
	}

	reposNotneededHooks := []string{
		"user2/repo1.wiki.git",
		"user30/empty.git",
	}

	err := listSubDir(setting.RepoRootPath, func(dir, userName string) error {
		return listSubDir(dir, func(dir, repoName string) error {
			fullName := path.Join(userName, repoName)

			if !util.SliceContains(neededReops, fullName) {
				return util.RemoveAll(dir)
			}

			if util.SliceContains(reposNotneededHooks, fullName) {
				return util.RemoveAll(path.Join(dir, "hooks"))
			}

			// proc-receive is not needed in test  code now
			_ = util.Remove(path.Join(dir, "hooks", "proc-receive"))

			for _, fix := range allFixs {
				err := os.MkdirAll(path.Join(dir, fix.Path), os.ModePerm)
				if err != nil {
					return err
				}

				err = os.WriteFile(path.Join(dir, fix.Path, fix.Name), []byte(fix.Content), 0o777)
				if err != nil {
					return err
				}
			}

			return nil
		})
	})
	if err != nil {
		log.Fatal("fixAllGiteaHook: %v", err)
	}
}

func initDev(pathToGiteaRoot string) {
	setting.CustomConf = filepath.Join(pathToGiteaRoot, "tests", "dev.ini")
	setting.CustomPath = pathToGiteaRoot

	setting.InitCfgProvider(setting.CustomConf)
	setting.LoadCommonSettings()

	routers.InitWebInstalled(graceful.GetManager().HammerContext())

	fixturesDir := filepath.Join(pathToGiteaRoot, "models", "fixtures")
	if err := unittest.InitFixtures(unittest.FixturesOptions{
		Dir: fixturesDir,
	}); err != nil {
		log.Fatal("CreateTestEngine: %+v", err)
	}
	db.SetLogSQL(db.DefaultContext, true)

	if err := unittest.LoadFixtures(); err != nil {
		log.Fatal("LoadFixtures: %v", err)
	}

	if err := setting.PrepareAppDataPath(); err != nil {
		log.Fatal("Can not prepare APP_DATA_PATH: %v", err)
	}
}

func runHTTP(network, listenAddr, name string, m http.Handler, useProxyProtocol bool) error {
	return graceful.HTTPListenAndServe(network, listenAddr, name, m, useProxyProtocol)
}

func removeNotNeededFixtures(pathToGiteaRoot string) {
	nootNeededFixtures := []string{
		"version.yml",
		"app_state.yml",
		"sqlite_sequence.yml",
	}
	keptFiles := []string{
		"gpg_key.yml",
		"deploy_key.yml",
		"external_login_user.yml",
		"gpg_key_import.yml",
		"login_source.yml",
		"protected_branch.yml",
		"repo_archiver.yml",
		"repo_indexer_status.yml",
	}

	err := filepath.Walk(path.Join(pathToGiteaRoot, "models", "fixtures"), func(pth string, info fs.FileInfo, _ error) error {
		if info.IsDir() {
			return nil
		}

		fileName := path.Base(pth)
		if !strings.HasSuffix(fileName, ".yml") {
			return nil
		}

		if util.SliceContains(nootNeededFixtures, fileName) {
			return os.Remove(pth)
		}

		if util.SliceContains(keptFiles, fileName) {
			return nil
		}

		content, err := os.ReadFile(pth)
		if err != nil {
			return err
		}

		result := make([]map[string]interface{}, 0, 10)
		err = yaml.Unmarshal(content, &result)
		if err != nil {
			return err
		}
		if len(result) == 0 {
			log.Info("remove empty file: %s", fileName)
			return os.Remove(pth)
		}

		return nil
	})
	if err != nil {
		log.Fatal("removeNotNeededFixtures: %v", err)
	}
}
