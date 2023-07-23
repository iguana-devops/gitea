// Copyright 2023 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package openapi

import (
	"fmt"
	"io"
	"net/url"

	"code.gitea.io/gitea/modules/markup"
	"code.gitea.io/gitea/modules/setting"

	"github.com/gobwas/glob"
)

func init() {
	markup.RegisterRenderer(Renderer{})
}

// Renderer implements markup.Renderer for asciicast files.
// See https://github.com/asciinema/asciinema/blob/develop/doc/asciicast-v2.md
type Renderer struct{}

var _ markup.GlobMatchRenderer = (*Renderer)(nil)

// Name implements markup.Renderer
func (Renderer) Name() string {
	return "openapi"
}

// SanitizerDisabled disabled sanitize if return true
func (Renderer) SanitizerDisabled() bool {
	return true
}

func (Renderer) DisplayInNewPage() bool {
	return true
}

func (Renderer) MatchGlobs() []glob.Glob {
	return []glob.Glob{
		glob.MustCompile("**{openapi,OpenAPI,swagger}.{yml,yaml,json,JSON,Yaml,YML}", '/'),
	}
}

// Extensions implements markup.Renderer
func (Renderer) Extensions() []string {
	return nil
}

// SanitizerRules implements markup.Renderer
func (Renderer) SanitizerRules() []setting.MarkupSanitizerRule {
	return []setting.MarkupSanitizerRule{
		{Element: "script", AllowAttr: "src"},
	}
}

// Render implements markup.Renderer
func (Renderer) Render(ctx *markup.RenderContext, _ io.Reader, output io.Writer) error {
	rawURL := fmt.Sprintf("%s/%s/%s/raw/%s/%s",
		setting.AppSubURL,
		url.PathEscape(ctx.Metas["user"]),
		url.PathEscape(ctx.Metas["repo"]),
		ctx.Metas["BranchNameSubURL"],
		ctx.RelativePath,
	)

	if _, err := io.WriteString(output, fmt.Sprintf(
		`<!DOCTYPE html>
<html>
<head>
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<link rel="stylesheet" href="%s/assets/css/swagger.css?v=%s">
</head>
<body>
	<div id="swagger-ui" data-source="%s"></div>
	<script src="%s/assets/js/swagger.js?v=%s"></script>
</body>
</html>`,
		setting.StaticURLPrefix,
		setting.AssetVersion,
		rawURL,
		setting.StaticURLPrefix,
		setting.AssetVersion,
	)); err != nil {
		return err
	}
	return nil
}
