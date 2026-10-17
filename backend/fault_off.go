//go:build !faulthook

package backend

// faultHook is nil in normal builds. See fault_on.go.
var faultHook func(role string) error
