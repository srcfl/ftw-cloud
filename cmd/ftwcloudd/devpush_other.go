//go:build !ftwclouddev

package main

import (
	"context"
	"errors"
	"log/slog"

	"github.com/srcfl/ftw-cloud/internal/push"
	"github.com/srcfl/ftw-cloud/internal/registry"
)

// captureSender exists only in development builds.
func captureSender(string) (push.Sender, error) {
	return nil, errors.New("-dev-apns-capture needs a build with -tags ftwclouddev")
}

// serveDevPush exists only in development builds.
func serveDevPush(context.Context, string, *registry.Registry, *push.Service, *slog.Logger) error {
	return errors.New("-dev-push-listen needs a build with -tags ftwclouddev")
}
