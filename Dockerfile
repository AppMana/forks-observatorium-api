FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine3.23@sha256:754d5200fc3edae76d3b6598a9a3fac7e74981ee6a5413ab955025f185753ef2 AS builder

ARG TARGETOS
ARG TARGETARCH
ENV GOTOOLCHAIN=local GOMAXPROCS=2

RUN apk add --update --no-cache 'ca-certificates>=20261020-r0' tzdata git make bash && update-ca-certificates

ADD . /opt
WORKDIR /opt

RUN git update-index --refresh; make build OS=${TARGETOS} ARCH=${TARGETARCH}

FROM alpine:3.23@sha256:ff7f0c727dd796aa36787bfcd9a64bf35a6ce72a73451b3359fde849b6703d63 AS runner

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /opt/observatorium-api /bin/observatorium-api

ARG BUILD_DATE
ARG VERSION
ARG VCS_REF
ARG DOCKERFILE_PATH

USER 10000:10000

LABEL vendor="Observatorium" \
    name="observatorium/api" \
    description="Observatorium API" \
    io.k8s.display-name="observatorium/api" \
    io.k8s.description="Observatorium API" \
    maintainer="Observatorium <team-monitoring@redhat.com>" \
    version="$VERSION" \
    org.label-schema.build-date=$BUILD_DATE \
    org.label-schema.description="Observatorium API" \
    org.label-schema.docker.cmd="docker run --rm observatorium/api" \
    org.label-schema.docker.dockerfile=$DOCKERFILE_PATH \
    org.label-schema.name="observatorium/api" \
    org.label-schema.schema-version="1.0" \
    org.label-schema.vcs-branch=$VCS_BRANCH \
    org.label-schema.vcs-ref=$VCS_REF \
    org.label-schema.vcs-url="https://github.com/observatorium/api" \
    org.label-schema.vendor="observatorium/api" \
    org.label-schema.version=$VERSION


ENTRYPOINT ["/bin/observatorium-api"]
