//! Compile the control-plane protobuf into Rust with prost.
//!
//! Requires the `protoc` compiler on `PATH` (Arch: `pacman -S protobuf`). This
//! is a build-time-only dependency; the generated code has no runtime tie to
//! protoc. See `proto/control.proto`.

fn main() {
    println!("cargo:rerun-if-changed=proto/control.proto");
    // Suppress prost's field-dumping `Debug` for `SharedKeyHandoff` (M5d slice
    // 015 / LEAK-1): that message carries raw `S` in a `bytes` field, so the
    // default derived `Debug` would print the key in clear if the frame were
    // ever `{:?}`-formatted (a panic-with-frame, a stray `dbg!`). We hand-write a
    // redacting `Debug` in `proto.rs` instead; skipping the derive here is what
    // lets that manual impl exist without a conflicting one. Every enclosing type
    // (`frame::Kind`, `Frame`, `CeremonyOutcome::Handoff`) then routes through the
    // redacting impl for free.
    prost_build::Config::new()
        .skip_debug(["softfig.net.control.v1.SharedKeyHandoff"])
        .compile_protos(&["proto/control.proto"], &["proto"])
        .expect("compile proto/control.proto (is `protoc` installed?)");
}
