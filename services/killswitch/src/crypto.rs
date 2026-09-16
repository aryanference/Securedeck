use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::convert::TryFrom;

pub fn verify_command(
    public_key: &VerifyingKey,
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), &'static str> {
    let sig = Signature::try_from(signature_bytes).map_err(|_| "Invalid signature format")?;
    
    match public_key.verify(message, &sig) {
        Ok(_) => Ok(()),
        Err(_) => Err("Signature verification failed"),
    }
}
