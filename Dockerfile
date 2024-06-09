FROM debian:latest

RUN apt-get update && \
    apt-get install -y \
    curl \
    git \
    build-essential \
    && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /home
RUN git clone https://github.com/aws/aws-nitro-enclaves-nsm-api.git
WORKDIR /home/aws-nitro-enclaves-nsm-api
RUN cargo build --release
WORKDIR /home/aws-nitro-enclaves-nsm-api/nsm-lib
RUN cargo build --release
RUN cp /home/aws-nitro-enclaves-nsm-api/target/release/libnsm.a /usr/lib
RUN cp /home/aws-nitro-enclaves-nsm-api/target/release/nsm.h /usr/include
WORKDIR /home
