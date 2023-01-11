// Copyright 2022 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package setting

// Metrics settings
var Metrics = struct {
	Enabled                  bool
	Token                    string
	EnabledIssueByLabel      bool
	EnabledIssueByRepository bool
}{
	Enabled:                  false,
	Token:                    "",
	EnabledIssueByLabel:      false,
	EnabledIssueByRepository: false,
}

func parseMetricsSetting(rootCfg Config) {
	mustMapSetting(Cfg, "metrics", &Metrics)
}
