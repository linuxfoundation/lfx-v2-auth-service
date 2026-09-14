// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package errors

import (
	"errors"
	"time"
)

// Validation represents a validation error in the application.
type Validation struct {
	base
}

// Error returns the error message for Validation.
func (v Validation) Error() string {
	return v.error()
}

// NewValidation creates a new Validation error with the provided message.
func NewValidation(message string, err ...error) Validation {
	return Validation{
		base: base{
			message: message,
			err:     errors.Join(err...),
		},
	}
}

// Unauthorized represents an unauthorized error in the application.
type Unauthorized struct {
	base
}

// Error returns the error message for Unauthorized.
func (u Unauthorized) Error() string {
	return u.error()
}

// NewUnauthorized creates a new Unauthorized error with the provided message.
func NewUnauthorized(message string, err ...error) Unauthorized {
	return Unauthorized{
		base: base{
			message: message,
			err:     errors.Join(err...),
		},
	}
}

// Forbidden represents a forbidden error in the application.
type Forbidden struct {
	base
}

// Error returns the error message for Forbidden.
func (f Forbidden) Error() string {
	return f.error()
}

// NewForbidden creates a new Forbidden error with the provided message.
func NewForbidden(message string, err ...error) Forbidden {
	return Forbidden{
		base: base{
			message: message,
			err:     errors.Join(err...),
		},
	}
}

// NotFound represents a not found error in the application.
type NotFound struct {
	base
}

// Error returns the error message for NotFound.
func (v NotFound) Error() string {
	return v.error()
}

// NewNotFound creates a new NotFound error with the provided message.
func NewNotFound(message string, err ...error) NotFound {
	return NotFound{
		base: base{
			message: message,
			err:     errors.Join(err...),
		},
	}
}

// Conflict represents a conflict error in the application.
type Conflict struct {
	base
}

// Error returns the error message for Conflict.
func (c Conflict) Error() string {
	return c.error()
}

// NewConflict creates a new Conflict error with the provided message.
func NewConflict(message string, err ...error) Conflict {
	return Conflict{
		base: base{
			message: message,
			err:     errors.Join(err...),
		},
	}
}

// RateLimited reports that an upstream refused the call because a rate limit is
// exhausted, carrying the server's Retry-After hint when it gave one.
//
// Return it BARE, never through NewUnexpected. The types here hold a wrapped
// error for their message but implement no Unwrap, so a wrapped RateLimited is
// invisible to errors.As and the caller falls back to its generic failure path
// — which for the events consumer means spending one of an event's bounded
// attempts on a wait that was never that event's fault.
type RateLimited struct {
	base
	// RetryAfter is the server's hint, or zero when the header was absent,
	// unparseable, or already in the past.
	RetryAfter time.Duration
}

// Error returns the error message for RateLimited.
func (r RateLimited) Error() string {
	return r.error()
}

// NewRateLimited creates a new RateLimited error with the provided message and
// the server's retry hint.
func NewRateLimited(message string, retryAfter time.Duration, err ...error) RateLimited {
	return RateLimited{
		base: base{
			message: message,
			err:     errors.Join(err...),
		},
		RetryAfter: retryAfter,
	}
}
