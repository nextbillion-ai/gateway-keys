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
    apt-get install libssl1.1:amd64 && \
    apt-get install wget python3 -y && \
    rm -rf /var/lib/apt/lists/*

RUN wget --no-check-certificate https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-sdk-322.0.0-linux-x86_64.tar.gz
RUN tar zxf google-cloud-sdk-322.0.0-linux-x86_64.tar.gz
RUN rm google-cloud-sdk-322.0.0-linux-x86_64.tar.gz
ENV PATH=$PATH:google-cloud-sdk/bin

CMD ./gateway-keys
