tags:
	rusty-tags vi

build-linux:
	cargo build --target x86_64-unknown-linux-musl --release

.PHONY: tags
