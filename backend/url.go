// Copyright (c) 2026 bjd5o
// SPDX-License-Identifier: MPL-2.0

package backend

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

func normalizeKanidmURL(raw string) (string, error) {
	origin := strings.TrimRight(strings.TrimSpace(raw), "/")
	if origin == "" {
		return "", errors.New("url is required")
	}
	u, err := url.Parse(origin)
	if err != nil {
		return "", fmt.Errorf("invalid url: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", fmt.Errorf("invalid url %q: scheme must be https or http", origin)
	}
	if u.Host == "" {
		return "", fmt.Errorf("invalid url %q: missing host", origin)
	}
	return origin, nil
}
