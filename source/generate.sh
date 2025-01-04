#!/usr/bin/bash -xeu
rm -f generated/jsonschema/*.json
cd openfdap
cargo run --bin generate_jsonschema