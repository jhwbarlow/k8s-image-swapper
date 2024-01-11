FROM golang:1.18 AS build
WORKDIR /tmp/src
COPY . ./
RUN ls -l cmd && ls -l pkg && ls -l vendor && ls -l *.go
RUN CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -v -o /tmp/build/k8s-image-swapper

FROM debian:trixie-slim AS release
COPY --from=build /tmp/build/k8s-image-swapper /usr/bin/k8s-image-swapper
# Ignore warning about not specifying exact version.
# ca-certificates package is just a collection of certs, we always want the latest.
# hadolint ignore=DL3008
RUN apt-get update \
      && apt-get install -y ca-certificates --no-install-recommends \
      && apt-get install -y skopeo=1.13.3+ds1-2 \
      && rm -rf /var/lib/apt/lists/*
USER nobody:nogroup
ENTRYPOINT ["/usr/bin/k8s-image-swapper"]
