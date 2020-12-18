FROM nextbillionai/rust:cargoc-20201120 as BUILD

RUN mkdir building
WORKDIR building

COPY src src
ADD Cargo.toml .
ADD Cargo.lock .
RUN bash -c "cargo build --release"

FROM debian:buster-20200908-slim 

COPY --from=BUILD /building/target/release/gateway-keys .

RUN apt-get update && \
    apt-get install libssl1.1:amd64 &&\
    rm -rf /var/lib/apt/lists/*

CMD ./gateway-keys
