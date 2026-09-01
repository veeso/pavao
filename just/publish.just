# Package and publish the crate to crates.io.
[group('publish')]
publish package args="":
  cargo publish --locked --package {{ package }} {{ args }}

[group('publish')]
publish_all args="":
  cargo publish --locked {{ args }}
