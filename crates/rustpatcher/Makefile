.PHONY: build-simple
build-simple:
	cargo build --release --example simple
	cargo run --bin rustpatcher sign ../../target/release/examples/simple --key-file ./owner_key

.PHONY: run-simple
run-simple:
	../../target/release/examples/simple

.PHONY: build-simple-copy
build-simple-copy:
	cargo build --release --example simple
	cargo run --bin rustpatcher sign ../../target/release/examples/simple --key-file ./owner_key
	cp ../../target/release/examples/simple ../../target/release/examples/simple_copy

.PHONY: run-simple-copy
run-simple-copy:
	../../target/release/examples/simple_copy