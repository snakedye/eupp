FROM rust:1.93-bookworm

WORKDIR /usr/src/eupp
COPY . .
RUN cp .env.template .env
RUN cargo build -p eupp --release && mv target/release/eupp /usr/local/bin/

EXPOSE 3333 9000

ENV EUPP_API_PORT=3333
ENV EUPP_P2P_PORT=9000

ENTRYPOINT ["eupp"]
