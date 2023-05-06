// Copyright 2023 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package queue

import (
	"context"
	"errors"
	"path/filepath"
	"strings"

	"code.gitea.io/gitea/modules/nosql"

	"gitea.com/lunny/levelqueue"
)

type baseLevelQueue struct {
	internal *levelqueue.Queue
	conn     string
	cfg      *BaseConfig
}

var _ baseQueue = (*baseLevelQueue)(nil)

func prepareLevelQueueConfig(cfg *BaseConfig) error {
	if cfg.ConnStr == "" { // use data dir as conn str
		dir := cfg.DataDir
		if !filepath.IsAbs(dir) {
			return errors.New("invalid leveldb data dir")
		}
		cfg.ConnStr = dir
	} else if !strings.HasPrefix(cfg.ConnStr, "leveldb://") {
		return errors.New("invalid leveldb connection string")
	}
	return nil
}

func newBaseLevelQueueGeneric(cfg *BaseConfig, unique bool) (baseQueue, error) {
	if unique {
		return newBaseLevelQueueUnique(cfg)
	}
	return newBaseLevelQueueSimple(cfg)
}

func newBaseLevelQueueSimple(cfg *BaseConfig) (baseQueue, error) {
	if err := prepareLevelQueueConfig(cfg); err != nil {
		return nil, err
	}

	q := &baseLevelQueue{conn: cfg.ConnStr, cfg: cfg}
	db, err := nosql.GetManager().GetLevelDB(q.conn)
	if err != nil {
		return nil, err
	}

	q.internal, err = levelqueue.NewQueue(db, []byte(cfg.QueueFullName), false)
	if err != nil {
		return nil, err
	}

	return q, nil
}

func (q *baseLevelQueue) PushItem(ctx context.Context, data []byte) error {
	return baseLevelQueueCommon(q.cfg, q.internal, nil).PushItem(ctx, data)
}

func (q *baseLevelQueue) PopItem(ctx context.Context) ([]byte, error) {
	return baseLevelQueueCommon(q.cfg, q.internal, nil).PopItem(ctx)
}

func (q *baseLevelQueue) HasItem(ctx context.Context, data []byte) (bool, error) {
	return false, nil
}

func (q *baseLevelQueue) Len(ctx context.Context) (int, error) {
	return int(q.internal.Len()), nil
}

func (q *baseLevelQueue) Close() error {
	err := q.internal.Close()
	_ = nosql.GetManager().CloseLevelDB(q.conn)
	return err
}

func (q *baseLevelQueue) RemoveAll(ctx context.Context) error {
	for q.internal.Len() > 0 {
		if _, err := q.internal.LPop(); err != nil {
			return err
		}
	}
	return nil
}
