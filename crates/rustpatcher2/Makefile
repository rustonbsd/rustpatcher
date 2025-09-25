.PHONY: build-owner
build-owner:
	cargo build --release --example owner
	cargo run --bin rustpatcher sign ../../target/release/examples/owner --key-file ./owner_key

run-owner: build-owner
	../../target/release/examples/owner