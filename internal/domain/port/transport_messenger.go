// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package port

// TransportMessenger represents the behavior of a message that can be sent to the committee API.
type TransportMessenger interface {
	Subject() string
	Data() []byte
	Respond(data []byte) error
}
