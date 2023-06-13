// Copyright 2023 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package elasticsearch

import (
	"context"
	"fmt"
	"time"

	"code.gitea.io/gitea/modules/log"

	"github.com/olivere/elastic/v7"
)

// VersionedIndexName returns the full index name with version
func (i *Indexer) VersionedIndexName() string {
	return versionedIndexName(i.indexName, i.version)
}

func versionedIndexName(indexName string, version int) string {
	return fmt.Sprintf("%s.v%d", indexName, version)
}

func (i *Indexer) createIndex(ctx context.Context) error {
	createIndex, err := i.Client.CreateIndex(i.VersionedIndexName()).BodyString(i.mapping).Do(ctx)
	if err != nil {
		return err
	}
	if !createIndex.Acknowledged {
		return fmt.Errorf("create index %s with %s failed", i.VersionedIndexName(), i.mapping)
	}

	i.checkOldIndexes(ctx)

	return nil
}

func (i *Indexer) initClient() (*elastic.Client, error) {
	opts := []elastic.ClientOptionFunc{
		elastic.SetURL(i.url),
		elastic.SetSniff(false),
		elastic.SetHealthcheckInterval(10 * time.Second),
		elastic.SetGzip(false),
	}

	logger := log.GetLogger(log.DEFAULT)

	opts = append(opts, elastic.SetTraceLog(&log.PrintfLogger{Logf: logger.Trace}))
	opts = append(opts, elastic.SetInfoLog(&log.PrintfLogger{Logf: logger.Info}))
	opts = append(opts, elastic.SetErrorLog(&log.PrintfLogger{Logf: logger.Error}))

	return elastic.NewClient(opts...)
}

func (i *Indexer) checkOldIndexes(ctx context.Context) {
	i.checkOldIndex(ctx, i.indexName) // Old index name without version
	for v := 1; v < i.version; v++ {
		i.checkOldIndex(ctx, versionedIndexName(i.indexName, v))
	}
}

func (i *Indexer) checkOldIndex(ctx context.Context, indexName string) {
	exists, err := i.Client.IndexExists(indexName).Do(ctx)
	if err == nil && exists {
		log.Warn("Found older elasticsearch index named %q, Gitea will keep the old NOT DELETED. You can delete the old version after the upgrade succeed.", indexName)
	}
}
