use std::collections::HashMap;

fn main() {
    // Only build zkVM artifacts when feature is enabled
    if std::env::var("CARGO_FEATURE_ZK_VM").is_err() {
        return;
    }

    // RISC0 0.21 expects a map of guest-name -> GuestOptions
    let mut guests = HashMap::new();

    guests.insert(
        "zkcg-zkvm-guest",
        risc0_build::GuestOptions {
            features: vec![],
            use_docker: None,
        },
    );

    risc0_build::embed_methods_with_options(guests);
}
