// Copyright 2022 The Gitea Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package activitypub

import (
	"net/http"
	"net/url"

	"code.gitea.io/gitea/modules/context"
	"code.gitea.io/gitea/modules/json"

	ap "github.com/go-ap/activitypub"
)

func AuthorizeInteraction(c *context.Context) {
	uri, err := url.Parse(c.Req.URL.Query().Get("uri"))
	if err != nil {
		c.ServerError("Could not parse URI", err)
		return
	}
	resp, err := Fetch(uri)
	if err != nil {
		c.ServerError("Fetch", err)
		return
	}

	var object map[string]interface{}
	err = json.Unmarshal(resp, &object)
	if err != nil {
		c.ServerError("Unmarshal", err)
		return
	}
	switch object["type"] {
	case "Person":
		var person ap.Person
		err = person.UnmarshalJSON(resp)
		if err != nil {
			c.ServerError("UnmarshalJSON", err)
			return
		}
		err = FederatedUserNew(c, person)
		if err != nil {
			c.ServerError("FederatedUserNew", err)
			return
		}
		name, err := personIRIToName(person.GetLink())
		if err != nil {
			c.ServerError("personIRIToName", err)
			return
		}
		c.Redirect(name)
		/*case "organization":
			// Do something idk
		case "repository":
			FederatedRepoNew() // TODO
		case "ticket":
			// TODO*/
	}

	c.Status(http.StatusOK)
}
