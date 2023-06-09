package saml_test

import (
	auth_model "code.gitea.io/gitea/models/auth"
	"code.gitea.io/gitea/services/auth"
	"code.gitea.io/gitea/services/auth/source/saml"
)

// This test file exists to assert that our Source exposes the interfaces that we expect
// It tightly binds the interfaces and implementation without breaking go import cycles

type sourceInterface interface {
	auth_model.Config
	auth_model.SourceSettable
	auth_model.RegisterableSource
	auth.PasswordAuthenticator
}

var _ (sourceInterface) = &saml.Source{}
