use wasm_bindgen::prelude::*;
use zkp_elliptic_curve::ScalarFieldElement;
use zkp_elliptic_curve_crypto::PrivateKey;
use zkp_elliptic_curve_crypto::PublicKey;
use zkp_elliptic_curve_crypto::Signature;
use zkp_u256::U256;
use sha2::{Sha256, Digest};

#[wasm_bindgen]
pub fn version() -> String {
    String::from("1.0")
}

#[wasm_bindgen]
pub fn get_pubkey(key: String) -> String {
    let private_key = PrivateKey::from(U256::from_hex_str(key.as_str()));
    let public_key = PublicKey::from(&private_key);
    serde_json::to_string(&public_key).unwrap()
}

#[wasm_bindgen]
pub fn sign(key: String, msg: String) -> String {
    let private_key = PrivateKey::from(U256::from_hex_str(key.as_str()));

    let msg_hash = format!("{:X}", Sha256::digest(msg.as_bytes()));
    let digest = ScalarFieldElement::from(U256::from_hex_str(msg_hash.as_str()));

    let signature = private_key.sign(&digest);

    serde_json::to_string(&signature).unwrap()
}

#[wasm_bindgen]
pub fn verify(pubkey_json: String, msg: String, signature_json: String) -> String {
    let public_key: PublicKey = serde_json::from_str(&pubkey_json).unwrap();

    let sig: Signature = serde_json::from_str(&signature_json).unwrap();

    let msg_hash = format!("{:X}", Sha256::digest(msg.as_bytes()));
    let digest = ScalarFieldElement::from(U256::from_hex_str(msg_hash.as_str()));

    let result = public_key.verify(&digest, &sig);

    serde_json::to_string(&result).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_sign() {
        let signature = sign(String::from("03c1e9550e66958296d11b60f8e8e7a7ad990d07fa65d5f7652c4a6c87d4e3cc"), String::from("Hello World"));
        assert_eq!(signature, r#"{"r":"0x050df7b9c226c8a6a21a9c9fdf4dc76f0a1fb77ef9c5ac4795f4d8b070176efd","w":"0x03004246e5e23c6b6d6112cc2fd5256d7c26cca9aca8c37de912175cf26cf101"}"#)
    }

    #[test]
    fn test_verify() {
        let sig = r#"{"r":"0x050df7b9c226c8a6a21a9c9fdf4dc76f0a1fb77ef9c5ac4795f4d8b070176efd","w":"0x03004246e5e23c6b6d6112cc2fd5256d7c26cca9aca8c37de912175cf26cf101"}"#;
        let res = verify(String::from("03c1e9550e66958296d11b60f8e8e7a7ad990d07fa65d5f7652c4a6c87d4e3cc"), String::from("Hello World"), sig);
        assert_eq!(res, true)
    }
}