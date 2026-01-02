
fn main() {
    // Only build zkVM artifacts when feature is enabled
    if std::env::var("CARGO_FEATURE_ZK_VM").is_err() {
        return;
    }

    // RISC0 0.21 expects a map of guest-name -> GuestOptions
   

    risc0_build::embed_methods();
}
