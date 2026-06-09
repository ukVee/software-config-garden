//! Compile the control-plane protobuf into Rust with prost.
//!
//! Requires the `protoc` compiler on `PATH` (Arch: `pacman -S protobuf`). This
//! is a build-time-only dependency; the generated code has no runtime tie to
//! protoc. See `proto/control.proto`.

fn main() {
    println!("cargo:rerun-if-changed=proto/control.proto");
    prost_build::compile_protos(&["proto/control.proto"], &["proto"])
        .expect("compile proto/control.proto (is `protoc` installed?)");
}
