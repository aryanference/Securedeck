fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("../../proto/killswitch/v1/killswitch.proto")?;
    // D5 Resolved: Single source of truth for protos
    Ok(())
}
