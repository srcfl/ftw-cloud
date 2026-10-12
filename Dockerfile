# ftwcloudd, built from this repository.
#
# The image carries the source it was built from, served at /source, because
# AGPL-3.0 asks that everyone who uses the service over a network can get the
# code running it.

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# No cgo: the SQLite driver is pure Go, so the binary runs on a static base.
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/ftwcloudd ./cmd/ftwcloudd
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
