//! The growlight fleet console binary (spec §11). Only built with the `gui`
//! feature (`cargo run -p softfig-growlight-gui --features gui --bin growlight-gui`);
//! the default `cargo check --workspace` never compiles it or the heavy `iced`
//! dependency. The actual window render is the §7b on-device deferred check.

fn main() -> iced::Result {
    softfig_growlight_gui::runtime::run()
}
