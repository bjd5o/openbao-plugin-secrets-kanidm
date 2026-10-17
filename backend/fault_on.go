//go:build faulthook

package backend

import (
	"os"
	"strings"
)

// FaultCrashAfterMintPrefix names roles that, in a faulthook build only,
// make the plugin process exit right after Kanidm mints the token and
// before the lease is recorded. The integration suite uses it to exercise
// WAL rollback end to end.
const FaultCrashAfterMintPrefix = "fault-crash-after-mint"

var faultHook = func(role string) error {
	if strings.HasPrefix(role, FaultCrashAfterMintPrefix) {
		os.Exit(3)
	}
	return nil
}
