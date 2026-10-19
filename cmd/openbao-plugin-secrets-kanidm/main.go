// Copyright (c) 2026 bjd5o
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"os"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/plugin"

	"openbao-plugin-secrets-kanidm/backend"
)

func main() {
	logger := hclog.New(&hclog.LoggerOptions{})

	if err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: backend.Factory,
	}); err != nil {
		logger.Error("plugin shutting down", "error", err)
		os.Exit(1)
	}
}
