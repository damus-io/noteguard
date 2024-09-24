tags:
	find src -name '*.rs' | xargs ctags

build-linux:
	cargo build --target x86_64-unknown-linux-musl --release

.PHONY: tags
