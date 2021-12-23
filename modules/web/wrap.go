// Copyright 2021 The Gitea Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package web

import (
	goctx "context"
	"net/http"

	"code.gitea.io/gitea/modules/context"
	"code.gitea.io/gitea/routers/common"
)

// Wrap converts all kinds of routes to standard library one
func Wrap(handlers ...interface{}) http.HandlerFunc {
	if len(handlers) == 0 {
		panic("No handlers found")
	}

	ourHandlers := make([]wrappedHandlerFunc, 0, len(handlers))

	for _, handler := range handlers {
		ourHandlers = append(ourHandlers, convertHandler(handler))
	}
	return wrapInternal(ourHandlers)
}

func wrapInternal(handlers []wrappedHandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		for i := 0; i < len(handlers); i++ {
			handler := handlers[i]
			others := handlers[i+1:]
			done, deferable := handler(resp, req, others...)
			if deferable != nil {
				defer deferable()
			}
			if done {
				return
			}
		}
	})
}

// Middle wrap a context function as a chi middleware
func Middle(f func(ctx *context.Context)) func(netx http.Handler) http.Handler {
	funcInfo := common.GetFuncInfo(f)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
			common.UpdateContextHandler(req.Context(), funcInfo)
			ctx := context.GetContext(req)
			f(ctx)
			if ctx.Written() {
				return
			}
			next.ServeHTTP(ctx.Resp, ctx.Req)
		})
	}
}

// MiddleCancel wrap a context function as a chi middleware
func MiddleCancel(f func(ctx *context.Context) goctx.CancelFunc) func(netx http.Handler) http.Handler {
	funcInfo := common.GetFuncInfo(f)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
			common.UpdateContextHandler(req.Context(), funcInfo)
			ctx := context.GetContext(req)
			cancel := f(ctx)
			if cancel != nil {
				defer cancel()
			}
			if ctx.Written() {
				return
			}
			next.ServeHTTP(ctx.Resp, ctx.Req)
		})
	}
}

// MiddleAPI wrap a context function as a chi middleware
func MiddleAPI(f func(ctx *context.APIContext)) func(netx http.Handler) http.Handler {
	funcInfo := common.GetFuncInfo(f)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
			common.UpdateContextHandler(req.Context(), funcInfo)
			ctx := context.GetAPIContext(req)
			f(ctx)
			if ctx.Written() {
				return
			}
			next.ServeHTTP(ctx.Resp, ctx.Req)
		})
	}
}
