// Copyright 2023 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package internal

// Indexer defines an basic indexer interface
type Indexer interface {
	// Init initializes the indexer
	// returns true if the index was opened/existed (with data populated), false if it was created/not-existed (with no data)
	Init() (bool, error)
	// Ping checks if the indexer is available
	Ping() bool
	// Close closes the indexer
	Close()
}
