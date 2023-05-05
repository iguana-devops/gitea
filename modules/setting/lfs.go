// Copyright 2019 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package setting

import (
	"encoding/base64"
	"fmt"
	"time"

	"code.gitea.io/gitea/modules/generate"
)

// LFS represents the configuration for Git LFS
var LFS = struct {
	StartServer     bool          `ini:"LFS_START_SERVER"`
	JWTSecretBase64 string        `ini:"LFS_JWT_SECRET"`
	JWTSecretBytes  []byte        `ini:"-"`
	HTTPAuthExpiry  time.Duration `ini:"LFS_HTTP_AUTH_EXPIRY"`
	MaxFileSize     int64         `ini:"LFS_MAX_FILE_SIZE"`
	LocksPagingNum  int           `ini:"LFS_LOCKS_PAGING_NUM"`

	*Storage
}{}

func loadLFSFrom(rootCfg ConfigProvider) error {
	sec := rootCfg.Section("server")
	if err := sec.MapTo(&LFS); err != nil {
		return fmt.Errorf("failed to map LFS settings: %v", err)
	}

	lfsSec := rootCfg.Section("lfs")
	storageType := lfsSec.Key("STORAGE_TYPE").MustString("")

	// Specifically default PATH to LFS_CONTENT_PATH
	// DEPRECATED should not be removed because users maybe upgrade from lower version to the latest version
	// if these are removed, the warning will not be shown
	deprecatedSetting(rootCfg, "server", "LFS_CONTENT_PATH", "lfs", "PATH", "v1.19.0")
	lfsSec.Key("PATH").MustString(sec.Key("LFS_CONTENT_PATH").String())

	var err error
	LFS.Storage, err = getStorage(rootCfg, lfsSec, "lfs", storageType)
	if err != nil {
		return err
	}

	// Rest of LFS service settings
	if LFS.LocksPagingNum == 0 {
		LFS.LocksPagingNum = 50
	}

	LFS.HTTPAuthExpiry = sec.Key("LFS_HTTP_AUTH_EXPIRY").MustDuration(20 * time.Minute)

	if !LFS.StartServer {
		return nil
	}

	LFS.JWTSecretBytes = make([]byte, 32)
	n, err := base64.RawURLEncoding.Decode(LFS.JWTSecretBytes, []byte(LFS.JWTSecretBase64))

	if err != nil || n != 32 {
		LFS.JWTSecretBase64, err = generate.NewJwtSecretBase64()
		if err != nil {
			return fmt.Errorf("Error generating JWT Secret for custom config: %v", err)
		}

		// Save secret
		sec.Key("LFS_JWT_SECRET").SetValue(LFS.JWTSecretBase64)
		if err := rootCfg.Save(); err != nil {
			return fmt.Errorf("Error saving JWT Secret for custom config: %v", err)
		}
	}

	return nil
}
