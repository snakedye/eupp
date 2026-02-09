FROM rust:1.87-bookworm

WORKDIR /usr/src/eupp
COPY . .
RUN cp .env.template .env
RUN cargo build -p eupp --release && mv target/release/eupp /usr/local/bin/

EXPOSE 3333
ENTRYPOINT ["eupp"]
