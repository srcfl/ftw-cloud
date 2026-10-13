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
      -o /out/ftwcloudd ./cmd/ftwcloudd
RUN mkdir -p /out/share && tar -czf /out/share/source.tar.gz \
      --exclude=./.git --exclude=./state . \
    && mkdir -p /out/state

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ftwcloudd /usr/local/bin/ftwcloudd
COPY --from=build /out/share/source.tar.gz /usr/share/ftw-cloud/source.tar.gz
COPY --from=build --chown=nonroot:nonroot /out/state /state
USER nonroot
EXPOSE 443
ENTRYPOINT ["/usr/local/bin/ftwcloudd"]
