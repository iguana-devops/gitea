// Copyright 2023 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package convert

import (
	"context"

	project_model "code.gitea.io/gitea/models/project"
	api "code.gitea.io/gitea/modules/structs"
)

func ToAPIProject(ctx context.Context, project *project_model.Project) (*api.Project, error) {
	apiProject := &api.Project{
		Title:       project.Title,
		Description: project.Description,
		BoardType:   uint8(project.BoardType),
		IsClosed:    project.IsClosed,
		Created:     project.CreatedUnix.AsTime(),
		Updated:     project.UpdatedUnix.AsTime(),
		Closed:      project.ClosedDateUnix.AsTime(),
	}

	_ = project.LoadRepo(ctx)
	if project.Repo != nil {
		apiProject.Repo = &api.RepositoryMeta{
			ID:       project.RepoID,
			Name:     project.Repo.Name,
			Owner:    project.Repo.OwnerName,
			FullName: project.Repo.FullName(),
		}
	}

	_ = project.LoadCreator(ctx)
	if project.Creator != nil {
		apiProject.Creator = &api.User{
			ID:       project.Creator.ID,
			UserName: project.Creator.Name,
			FullName: project.Creator.FullName,
		}
	}

	_ = project.LoadOwner(ctx)
	if project.Owner != nil {
		apiProject.Owner = &api.User{
			ID:       project.Owner.ID,
			UserName: project.Owner.Name,
			FullName: project.Owner.FullName,
		}
	}

	return apiProject, nil
}

func ToAPIProjectList(ctx context.Context, projects []*project_model.Project) ([]*api.Project, error) {
	result := make([]*api.Project, len(projects))
	var err error
	for i := range projects {
		result[i], err = ToAPIProject(ctx, projects[i])
		if err != nil {
			break
		}
	}
	if err != nil {
		return nil, err
	}
	return result, nil
}
