// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package design

import (
	"goa.design/goa/v3/dsl"
)

var _ = dsl.API("auth", func() {
	dsl.Title("LFX v2 Auth Service")
	dsl.Description("Authentication service providing NATS-based user management with health endpoints")
	dsl.Version("1.0")
})

// Service describes the health check service
var _ = dsl.Service("auth-service", func() {
	dsl.Description("Auth service")

	// Liveness probe endpoint
	dsl.Method("livez", func() {
		dsl.Description("Check if the service is alive.")
		dsl.Meta("swagger:generate", "false")
		dsl.Result(dsl.Bytes, func() {
			dsl.Example("OK")
		})
		dsl.HTTP(func() {
			dsl.GET("/livez")
			dsl.Response(dsl.StatusOK, func() {
				dsl.ContentType("text/plain")
			})
		})
	})

	// Provisioning webhook, called by an Auth0 Event Stream.
	//
	// The webhook destination supports static-secret auth only, so there is no
	// caller identity for the edge to pin and the handler performs the
	// authorization itself.
	dsl.Method("provision-cdp-uuid", func() {
		dsl.Description("Provision a CDP member for a newly verified user, from an Auth0 event.")
		dsl.Meta("swagger:generate", "false")

		dsl.Payload(func() {
			dsl.Attribute("authorization", dsl.String, "Static bearer secret configured on the event stream")
			dsl.Attribute("body", dsl.Bytes, "Auth0 event payload")
			dsl.Required("body")
		})

		dsl.Error("Unauthorized", dsl.String, "Missing or invalid bearer secret")
		dsl.Error("BadRequest", dsl.String, "Unparseable event payload")
		dsl.Error("InternalServerError", dsl.String, "Transient failure; the event should be redelivered")

		dsl.HTTP(func() {
			dsl.POST("/webhooks/auth0/cdp-provisioning")
			dsl.Header("authorization:Authorization")
			dsl.Body("body")
			dsl.Response(dsl.StatusNoContent)

			// The status code decides whether Auth0 redelivers, so these
			// mappings are correctness rather than cosmetics: a 4xx suppresses
			// retry and is reserved for permanently bad requests.
			dsl.Response("Unauthorized", dsl.StatusUnauthorized)
			dsl.Response("BadRequest", dsl.StatusBadRequest)
			dsl.Response("InternalServerError", dsl.StatusInternalServerError)
		})
	})

	// Readiness probe endpoint
	dsl.Method("readyz", func() {
		dsl.Description("Check if the service is ready to accept requests.")
		dsl.Meta("swagger:generate", "false")
		dsl.Result(dsl.Bytes, func() {
			dsl.Example("OK")
		})

		dsl.Error("ServiceUnavailable", dsl.String, "Service unavailable")

		dsl.HTTP(func() {
			dsl.GET("/readyz")
			dsl.Response(dsl.StatusOK, func() {
				dsl.ContentType("text/plain")
			})
			dsl.Response("ServiceUnavailable", dsl.StatusServiceUnavailable, func() {
				dsl.ContentType("text/plain")
			})
		})
	})
})
