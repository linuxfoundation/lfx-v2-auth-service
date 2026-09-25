// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package nats

import (
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/port"
	"github.com/nats-io/nats.go"
)

// natsTransportMessenger implements port.TransportMessenger for NATS messages
type natsTransportMessenger struct {
	msg *nats.Msg
}

// Subject returns the NATS message subject
func (n *natsTransportMessenger) Subject() string {
	return n.msg.Subject
}

// Data returns the NATS message data
func (n *natsTransportMessenger) Data() []byte {
	return n.msg.Data
}

// Respond sends a response to the NATS message
func (n *natsTransportMessenger) Respond(data []byte) error {
	return n.msg.Respond(data)
}

// NewTransportMessenger creates a new TransportMessenger from a NATS message
func NewTransportMessenger(msg *nats.Msg) port.TransportMessenger {
	return &natsTransportMessenger{
		msg: msg,
	}
}
