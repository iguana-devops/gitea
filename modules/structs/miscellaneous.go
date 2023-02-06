// Copyright 2015 The Gogs Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package structs

// SearchResults results of a successful search
type SearchResults struct {
	OK   bool          `json:"ok"`
	Data []*Repository `json:"data"`
}

// SearchError error of a failed search
type SearchError struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

// MarkdownOption markdown options
type MarkdownOption struct {
	// Text markdown to render
	//
	// in: body
	Text string
	// Mode to render
	//
	// in: body
	Mode string
	// Context to render
	//
	// in: body
	Context string
	// Is it a wiki page ?
	//
	// in: body
	Wiki bool
}

// MarkdownRender is a rendered markdown document
// swagger:response MarkdownRender
type MarkdownRender string

// ServerVersion wraps the version of the server
type ServerVersion struct {
	Version string `json:"version"`
}

// GitignoreTemplateInfo name and text of a gitignore template
type GitignoreTemplateInfo struct {
	Name   string `json:"name"`
	Source string `json:"source"`
}

// APIError is an api error with a message
type APIError struct {
	Message string `json:"message"`
	URL     string `json:"url"`
}
