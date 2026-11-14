# syntax=docker/dockerfile:1
#
# Catalog image for MCP registries (Glama builds the repository's root Dockerfile, runs it over stdio and calls
# tools/list to list and score the tools). It runs `dove mcp catalog`: it describes every tool and refuses every
# call, with no mailboxes, no keys and no network. It is not a way to run Dove; for that see the Quickstart and
# deploy/Containerfile (server image) or deploy/compose.yaml.
#
# Check it like a registry does:
#   docker build -t dove-catalog . && { printf '%s\n' \
#     '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"c","version":"0"}}}' \
#     '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'; } | docker run -i --rm dove-catalog
#
# Same pinned build image as deploy/Containerfile; keep both in step with rust-toolchain.toml.

FROM rust:1.100.0-bookworm@sha256:ade39a710ef85f3506cffcfec3e8a24ba090badef1dff2fb798f71d878833fea AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rustfmt.toml ./
COPY src ./src
# Embedded by src/update (the release signing key `dove upgrade` trusts).
COPY deploy/release/minisign.pub ./deploy/release/minisign.pub
RUN cargo build --release --locked --bin dove && install -D -m 0755 target/release/dove /out/dove

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
LABEL org.opencontainers.image.title="dove-catalog" \
      org.opencontainers.image.description="Dove's MCP tool catalog over stdio, for registries (no mailboxes; tool calls are refused)" \
      org.opencontainers.image.source="https://github.com/dominik-lenhart/dove" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/dove /usr/local/bin/dove
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/dove", "mcp", "catalog"]
