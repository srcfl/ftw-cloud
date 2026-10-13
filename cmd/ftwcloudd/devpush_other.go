//go:build !ftwclouddev

package main

import (
	"context"
	"errors"
	"log/slog"

	"github.com/srcfl/ftw-cloud/internal/push"
	"github.com/srcfl/ftw-cloud/internal/registry"
)

// serveDevPush exists only in development builds.
func serveDevPush(context.Context, string, *registry.Registry, *push.Service, *slog.Logger) error {
	return errors.New("-dev-push-listen needs a build with -tags ftwclouddev")
}
