// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package httpclient

import (
	"net/http"

	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
)

// ErrorFromStatusCode returns an error based on the http status code
func ErrorFromStatusCode(statusCode int, message string) error {
	switch statusCode {
	case http.StatusBadRequest:
		return errors.NewValidation(message)
	case http.StatusUnauthorized:
		return errors.NewUnauthorized(message)
	case http.StatusForbidden:
		return errors.NewForbidden(message)
	case http.StatusNotFound:
		return errors.NewNotFound(message)
	case http.StatusInternalServerError:
		return errors.NewUnexpected(message)
	}
	return errors.NewUnexpected(message)
}
