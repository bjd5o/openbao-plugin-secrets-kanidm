// Copyright (c) 2026 bjd5o
// SPDX-License-Identifier: MPL-2.0

//go:build !faulthook

package backend

// faultHook is nil in normal builds. See fault_on.go.
var faultHook func(role string) error
