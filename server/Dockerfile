# WELDAP server on AlmaLinux 9.
#   docker build -t weldap-server server/                     runtime image (the last stage)
#   docker build --target ca -t weldap-ca server/             device CA tool (offline admin container)
#   docker build --target test -t weldap-server:test server/  + the probe client (tests only)
#   docker build --target dev -t weldap-server:dev server/    toolchain for server/check.sh (fmt, clippy, tests, coverage)
# Run it with server/compose.yaml (or testdir/compose.yaml): read-only root, all capabilities dropped except
# IPC_LOCK (mlockall), no core dumps, unprivileged user, secrets as read-only files.
# The runtime image is AlmaLinux 9 micro with every executable removed: glibc and config, the server binary, and
# nothing an intruder could run (no shell, coreutils, package manager or openssl).

FROM almalinux:9@sha256:245f8aab832fe800aa42bdab5fad75ebbd8e0b4c9f24820a83c638b177857ae2 AS toolchain
RUN dnf -y install rust cargo gcc && dnf clean all

FROM toolchain AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock server.example.json ./
COPY src ./src
RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo test --release --locked && cargo build --release --locked \
    && install -D -m 0755 target/release/weldap-server /out/weldap-server \
    && install -D -m 0755 target/release/weldap-probe /out/weldap-probe

# Quality gates (server/check.sh mounts the source read-only). Never deployed. The distribution's rustc is built
# against the distribution's LLVM, so its llvm-profdata/llvm-cov read the coverage data rustc writes.
FROM toolchain AS dev
RUN dnf -y install rustfmt clippy llvm && dnf clean all
RUN --mount=type=cache,target=/root/.cargo/registry \
    cargo install cargo-llvm-cov --version 0.9.1 --locked --root /usr/local
ENV LLVM_COV=/usr/bin/llvm-cov LLVM_PROFDATA=/usr/bin/llvm-profdata CARGO_TARGET_DIR=/target
WORKDIR /src

# Device CA: openssl + the weldap-ca script. Never on the serving host's network (compose runs it with none).
FROM almalinux:9-minimal@sha256:6a245486786d3e92c8b4f97a98e2acd5ffa4d78ef1d5fefbd91a64a9965bcbf0 AS ca
RUN microdnf -y install openssl && microdnf clean all \
    && echo 'weldap:x:10001:10001:WELDAP CA:/nonexistent:/sbin/nologin' >>/etc/passwd \
    && echo 'weldap:x:10001:' >>/etc/group
COPY weldap-ca /usr/local/bin/weldap-ca
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/weldap-ca"]

# AlmaLinux 9 micro, stripped: user entry added, then every executable deleted (rm deletes itself last).
FROM quay.io/almalinuxorg/9-micro:9@sha256:ae1fd0bbbe21c02a25c6f2db88277475e58baf9e8c6af26096b46c1c0601e699 AS rootfs
RUN echo 'weldap:x:10001:10001:WELDAP server:/nonexistent:/sbin/nologin' >>/etc/passwd \
    && echo 'weldap:x:10001:' >>/etc/group \
    && rm -rf /usr/sbin /usr/libexec /usr/local /var/cache /usr/share/doc /usr/share/man \
    && rm -rf /usr/bin/*

FROM scratch AS base
COPY --from=rootfs / /
COPY --from=build /out/weldap-server /usr/local/bin/weldap-server
USER 10001:10001
EXPOSE 8636
ENTRYPOINT ["/usr/local/bin/weldap-server"]
CMD ["serve", "--config", "/etc/weldap/server.json"]

# Test image: the runtime plus the probe client (testdir only; never deploy this one).
FROM base AS test
COPY --from=build /out/weldap-probe /usr/local/bin/weldap-probe

# Runtime image. Last, so a plain `docker build` produces it and never the test image.
FROM base AS runtime
