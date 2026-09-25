// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package converters

// StringPtr converts a string value to a string pointer
func StringPtr(s string) *string {
	return &s
}
