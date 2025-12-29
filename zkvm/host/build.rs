fn main() {
    // Cargo exposes enabled features as env vars:
    // CARGO_FEATURE_<FEATURE_NAME_IN_CAPS>
    if std::env::var("CARGO_FEATURE_ZK_VM").is_err() {
        // zk-vm feature not enabled → do nothing
        return;
    }

    risc0_build::embed_methods();
}
