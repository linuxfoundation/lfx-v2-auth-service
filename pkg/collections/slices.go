// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package collections

// RemoveFromSlice returns a new slice containing only the elements for which condition returns false.
func RemoveFromSlice[T comparable](slice []T, condition func(T) bool) []T {
	out := slice[:0]
	for _, item := range slice {
		if !condition(item) {
			out = append(out, item)
		}
	}
	return out
}
