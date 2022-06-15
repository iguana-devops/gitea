// Copyright 2022 The Gitea Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package activitypub

import (
	user_model "code.gitea.io/gitea/models/user"
)

const (
	userActivitypubPrivpem = "activitypub_privpem"
	userActivitypubPubpem  = "activitypub_pubpem"
)

// GetKeyPair function
func GetKeyPair(user *user_model.User) (pub, priv string, err error) {
	var settings map[string]*user_model.Setting
	if settings, err = user_model.GetUserSettings(user.ID, []string{userActivitypubPrivpem, userActivitypubPubpem}); err != nil {
		return
	} else if len(settings) == 0 {
		if priv, pub, err = GenerateKeyPair(); err != nil {
			return
		}
		if err = user_model.SetUserSetting(user.ID, userActivitypubPrivpem, priv); err != nil {
			return
		}
		if err = user_model.SetUserSetting(user.ID, userActivitypubPubpem, pub); err != nil {
			return
		}
		return
	} else {
		priv = settings[userActivitypubPrivpem].SettingValue
		pub = settings[userActivitypubPubpem].SettingValue
		return
	}
}

// GetPublicKey function
func GetPublicKey(user *user_model.User) (pub string, err error) {
	pub, _, err = GetKeyPair(user)
	return
}

// GetPrivateKey function
func GetPrivateKey(user *user_model.User) (priv string, err error) {
	_, priv, err = GetKeyPair(user)
	return
}
