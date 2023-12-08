// Copyright 2020 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package db

import (
	"context"

	"code.gitea.io/gitea/modules/setting"

	"xorm.io/builder"
	"xorm.io/xorm"
)

const (
	// DefaultMaxInSize represents default variables number on IN () in SQL
	DefaultMaxInSize     = 50
	defaultFindSliceSize = 10
)

// Paginator is the base for different ListOptions types
type Paginator interface {
	GetSkipTake() (skip, take int)
	GetStartEnd() (start, end int)
	IsListAll() bool
}

// GetPaginatedSession creates a paginated database session
func GetPaginatedSession(p Paginator) *xorm.Session {
	skip, take := p.GetSkipTake()

	return x.Limit(take, skip)
}

// SetSessionPagination sets pagination for a database session
func SetSessionPagination(sess Engine, p Paginator) *xorm.Session {
	skip, take := p.GetSkipTake()

	return sess.Limit(take, skip)
}

// SetEnginePagination sets pagination for a database engine
func SetEnginePagination(e Engine, p Paginator) Engine {
	skip, take := p.GetSkipTake()

	return e.Limit(take, skip)
}

// ListOptions options to paginate results
type ListOptions struct {
	PageSize int
	Page     int  // start from 1
	ListAll  bool // if true, then PageSize and Page will not be taken
}

var ListOptionsAll = ListOptions{ListAll: true}

var (
	_ Paginator   = &ListOptions{}
	_ FindOptions = ListOptions{}
)

// GetSkipTake returns the skip and take values
func (opts *ListOptions) GetSkipTake() (skip, take int) {
	opts.SetDefaultValues()
	return (opts.Page - 1) * opts.PageSize, opts.PageSize
}

// GetStartEnd returns the start and end of the ListOptions
func (opts *ListOptions) GetStartEnd() (start, end int) {
	start, take := opts.GetSkipTake()
	end = start + take
	return start, end
}

func (opts ListOptions) GetPage() int {
	return opts.Page
}

func (opts ListOptions) GetPageSize() int {
	return opts.PageSize
}

// IsListAll indicates PageSize and Page will be ignored
func (opts ListOptions) IsListAll() bool {
	return opts.ListAll
}

// SetDefaultValues sets default values
func (opts *ListOptions) SetDefaultValues() {
	if opts.PageSize <= 0 {
		opts.PageSize = setting.API.DefaultPagingNum
	}
	if opts.PageSize > setting.API.MaxResponseItems {
		opts.PageSize = setting.API.MaxResponseItems
	}
	if opts.Page <= 0 {
		opts.Page = 1
	}
}

func (opts ListOptions) ToConds() builder.Cond {
	return builder.NewCond()
}

// AbsoluteListOptions absolute options to paginate results
type AbsoluteListOptions struct {
	skip int
	take int
}

var _ Paginator = &AbsoluteListOptions{}

// NewAbsoluteListOptions creates a list option with applied limits
func NewAbsoluteListOptions(skip, take int) *AbsoluteListOptions {
	if skip < 0 {
		skip = 0
	}
	if take <= 0 {
		take = setting.API.DefaultPagingNum
	}
	if take > setting.API.MaxResponseItems {
		take = setting.API.MaxResponseItems
	}
	return &AbsoluteListOptions{skip, take}
}

// IsListAll will always return false
func (opts *AbsoluteListOptions) IsListAll() bool {
	return false
}

// GetSkipTake returns the skip and take values
func (opts *AbsoluteListOptions) GetSkipTake() (skip, take int) {
	return opts.skip, opts.take
}

// GetStartEnd returns the start and end values
func (opts *AbsoluteListOptions) GetStartEnd() (start, end int) {
	return opts.skip, opts.skip + opts.take
}

// FindOptions represents a find options
type FindOptions interface {
	GetPage() int
	GetPageSize() int
	IsListAll() bool
	ToConds() builder.Cond
}

type FindOptionsOrder interface {
	ToOrders() string
}

// Find represents a common find function which accept an options interface
func Find[T any](ctx context.Context, opts FindOptions) ([]*T, error) {
	sess := GetEngine(ctx).Where(opts.ToConds())
	page, pageSize := opts.GetPage(), opts.GetPageSize()
	if !opts.IsListAll() && pageSize > 0 && page >= 1 {
		sess.Limit(pageSize, (page-1)*pageSize)
	}
	if newOpt, ok := opts.(FindOptionsOrder); ok && newOpt.ToOrders() != "" {
		sess.OrderBy(newOpt.ToOrders())
	}

	findPageSize := defaultFindSliceSize
	if pageSize > 0 {
		findPageSize = pageSize
	}
	objects := make([]*T, 0, findPageSize)
	if err := sess.Find(&objects); err != nil {
		return nil, err
	}
	return objects, nil
}

// Count represents a common count function which accept an options interface
func Count[T any](ctx context.Context, opts FindOptions) (int64, error) {
	var object T
	return GetEngine(ctx).Where(opts.ToConds()).Count(&object)
}

// FindAndCount represents a common findandcount function which accept an options interface
func FindAndCount[T any](ctx context.Context, opts FindOptions) ([]*T, int64, error) {
	sess := GetEngine(ctx).Where(opts.ToConds())
	page, pageSize := opts.GetPage(), opts.GetPageSize()
	if !opts.IsListAll() && pageSize > 0 && page >= 1 {
		sess.Limit(pageSize, (page-1)*pageSize)
	}
	if newOpt, ok := opts.(FindOptionsOrder); ok && newOpt.ToOrders() != "" {
		sess.OrderBy(newOpt.ToOrders())
	}

	findPageSize := defaultFindSliceSize
	if pageSize > 0 {
		findPageSize = pageSize
	}
	objects := make([]*T, 0, findPageSize)
	cnt, err := sess.FindAndCount(&objects)
	if err != nil {
		return nil, 0, err
	}
	return objects, cnt, nil
}
