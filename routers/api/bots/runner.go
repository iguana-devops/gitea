// Copyright 2022 The Gitea Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package bots

import (
	"context"

	"code.gitea.io/gitea/modules/log"
	"code.gitea.io/gitea/modules/web"
	runnerv1 "gitea.com/gitea/proto-go/runner/v1"
	"gitea.com/gitea/proto-go/runner/v1/runnerv1connect"

	"github.com/bufbuild/connect-go"
)

type RunnerService struct{}

func (s *RunnerService) Connect(
	ctx context.Context,
	req *connect.Request[runnerv1.ConnectRequest],
) (*connect.Response[runnerv1.ConnectResponse], error) {
	log.Info("Request headers: %v", req.Header())
	res := connect.NewResponse(&runnerv1.ConnectResponse{
		Stage: &runnerv1.Stage{
			RunnerUuid: "foobar",
			BuildUuid:  "foobar",
		},
	})
	res.Header().Set("Gitea-Version", "runnerv1")
	return res, nil
}

func (s *RunnerService) Accept(
	ctx context.Context,
	req *connect.Request[runnerv1.AcceptRequest],
) (*connect.Response[runnerv1.AcceptResponse], error) {
	log.Info("Request headers: %v", req.Header())
	res := connect.NewResponse(&runnerv1.AcceptResponse{
		JobId: 100,
	})
	res.Header().Set("Gitea-Version", "runnerv1")
	return res, nil
}

func runnerServiceRoute(r *web.Route) {
	compress1KB := connect.WithCompressMinBytes(1024)

	runnerService := &RunnerService{}
	connectPath, connecthandler := runnerv1connect.NewRunnerServiceHandler(
		runnerService,
		compress1KB,
	)

	r.Post(connectPath+"{name}", grpcHandler(connecthandler))
}
