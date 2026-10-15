# ftwcloudd, built from this repository.
#
# The image carries the source it was built from, served at /source, because
# AGPL-3.0 asks that everyone who uses the service over a network can get the
# code running it.

# Go cross-compiles, so CI builds the arm64 image on any runner without
# emulating arm64.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS TARGETARCH
# The commit, for X-Source-Revision. CI passes it; .git stays out of the
# build context, so Go cannot read it itself.
ARG REVISION=
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# No cgo: the SQLite driver is pure Go, so the binary runs on a static base.
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags "-s -w -X github.com/srcfl/ftw-cloud/internal/server.Revision=${REVISION}" \
      -o /out/ftwcloudd ./cmd/ftwcloudd \
    && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w" \
      -o /out/ftwkeysd ./cmd/ftwkeysd
RUN mkdir -p /out/share && tar -czf /out/share/source.tar.gz \
      --exclude=./.git --exclude=./state . \
    && mkdir -p /out/state /out/keys

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ftwcloudd /usr/local/bin/ftwcloudd
# The keys part, run as its own container and user (deploy/keys.md).
COPY --from=build /out/ftwkeysd /usr/local/bin/ftwkeysd
COPY --from=build /out/share/source.tar.gz /usr/share/ftw-cloud/source.tar.gz
# ftwcloudd runs as a user of its own, 65530, not distroless's shared
# nonroot. The host gives its files to the user the image names
# (ftw-cloud-own in deploy/bootstrap.sh).
COPY --from=build --chown=65530:65530 /out/state /state
# Owned by ftwkeysd's user, so a new volume mounted here starts out its own
# and ftwcloudd cannot read it.
COPY --from=build --chown=65533:65533 /out/keys /keys
USER 65530:65530
EXPOSE 443
ENTRYPOINT ["/usr/local/bin/ftwcloudd"]
