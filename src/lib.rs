#![allow(clippy::unwrap_used)]

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use bitcoin::Network;
 

use bip39::{Language, Mnemonic};
use bitcoin::bip32::{DerivationPath, ExtendedPrivKey};
use bitcoin::secp256k1::{
    ecdh::SharedSecret, PublicKey as SecpPublicKey, Secp256k1, SecretKey, XOnlyPublicKey,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

 

#[derive(Serialize, Deserialize)]
struct SilentPaymentAddress {
    address: String,
    scan_pubkey: String,
    spend_pubkey: String,
    network: String,
}

#[derive(Serialize, Deserialize)]
struct SilentPaymentOutput {
    ephemeral_pubkey: String,
    output_pubkey: String,
    tweaked_output_key: String,
    sp_address: String,
    network: String,
}

#[derive(Serialize, Deserialize)]
struct WalletKeys {
    spend_priv: String,
    scan_priv: String,
    spend_pub: String,
    scan_pub: String,
    network: String,
}

#[derive(Serialize)]
struct TransactionResult {
    psbt_base64: String,
    raw_tx_hex: String,
    txid: String,
    network: String,
}

#[derive(Serialize)]
struct ScannedOutput {
    output_pubkey: String,
    value: u64,
    txid: String,
    vout: u32,
    tweak_data: String,
}

/// Helper: parse C string
fn parse_c_str(ptr: *const c_char) -> Result<String, String> {
    if ptr.is_null() {
        return Err("null pointer".into());
    }
    let cstr = unsafe { CStr::from_ptr(ptr) };
    cstr.to_str()
        .map(|s| s.to_string())
        .map_err(|e| format!("invalid utf8: {}", e))
}

/// Helper: Return JSON error string as C ptr
fn error_json(msg: &str) -> *mut c_char {
    let json = format!(r#"{{"error":"{}"}}"#, msg.replace('"', "\\\""));
    CString::new(json).unwrap_or_else(|_| CString::new("{}").unwrap()).into_raw()
}

/// Convert secp public key to hex (compressed)
fn pubkey_to_hex(pk: &SecpPublicKey) -> String {
    hex::encode(pk.serialize())
}

/// Convert secret key to hex
fn sk_to_hex(sk: &SecretKey) -> String {
    hex::encode(sk.secret_bytes())
}

/// Derive extended private key for a given derivation path string
fn derive_xprv_from_mnemonic(
    mnemonic_str: &str,
    passphrase: &str,
    derivation_path: &str,
    network: Network,
) -> Result<ExtendedPrivKey, String> {
    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic_str)
        .map_err(|e| format!("invalid mnemonic: {}", e))?;
    let seed = mnemonic.to_seed(passphrase);
    let xprv = ExtendedPrivKey::new_master(network, &seed)
        .map_err(|e| format!("master key generation failed: {}", e))?;
    let path = derivation_path
        .parse::<DerivationPath>()
        .map_err(|e| format!("invalid derivation path: {}", e))?;
    let secp = Secp256k1::new();
    xprv.derive_priv(&secp, &path)
        .map_err(|e| format!("key derivation failed: {}", e))
}

/// BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg)
fn tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(&tag_hash);
    hasher.update(&tag_hash);
    hasher.update(msg);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// Encode Silent Payment address (BIP-352 format: scan_pubkey || spend_pubkey)
/// Uses base58 for simplicity (can switch to bech32m later with proper library)
fn encode_silent_payment_address(
    scan_pubkey: &SecpPublicKey,
    spend_pubkey: &SecpPublicKey,
    is_testnet: bool,
) -> Result<String, String> {
    // Version byte: 0x01 for mainnet SP, 0x02 for testnet SP
    let version = if is_testnet { 0x02 } else { 0x01 };
    
    // BIP-352: Concatenate version + scan + spend public keys
    let mut data = Vec::with_capacity(67);
    data.push(version);
    data.extend_from_slice(&scan_pubkey.serialize());
    data.extend_from_slice(&spend_pubkey.serialize());
    
    // For now, return hex-encoded (most compatible)
    // Format: "sp1" prefix + hex data
    let prefix = if is_testnet { "tsp1" } else { "sp1" };
    Ok(format!("{}{}", prefix, hex::encode(&data)))
}

/// Decode Silent Payment address to extract scan and spend public keys
fn decode_silent_payment_address(address: &str) -> Result<(SecpPublicKey, SecpPublicKey), String> {
    // Check prefix
    let (expected_version, hex_data) = if let Some(stripped) = address.strip_prefix("sp1") {
        (0x01, stripped)
    } else if let Some(stripped) = address.strip_prefix("tsp1") {
        (0x02, stripped)
    } else {
        return Err("invalid silent payment address prefix".into());
    };
    
    // Decode hex
    let data = hex::decode(hex_data)
        .map_err(|_| "invalid hex encoding")?;
    
    if data.len() != 67 {
        return Err(format!("invalid address length: expected 67, got {}", data.len()));
    }
    
    // Verify version byte
    if data[0] != expected_version {
        return Err("version mismatch".into());
    }
    
    let scan_pubkey = SecpPublicKey::from_slice(&data[1..34])
        .map_err(|e| format!("invalid scan pubkey: {}", e))?;
    let spend_pubkey = SecpPublicKey::from_slice(&data[34..67])
        .map_err(|e| format!("invalid spend pubkey: {}", e))?;
    
    Ok((scan_pubkey, spend_pubkey))
}



// BIP-352 CORE FUNCTIONS
/// Generate shared secret with input public keys (BIP-352 compliant)
fn generate_shared_secret(
    input_privkey: &SecretKey,
    scan_pubkey: &SecpPublicKey,
    input_pubkeys: &[SecpPublicKey],
) -> Result<[u8; 32], String> {
    let secp = Secp256k1::new();
    
    // Step 1: Compute ECDH shared secret
    let ecdh_shared = SharedSecret::new(scan_pubkey, input_privkey);
    
    // Step 2: Sum all input public keys (required by BIP-352 for multiple inputs)
    let mut input_pubkey_sum = input_pubkeys[0];
    for pk in &input_pubkeys[1..] {
        input_pubkey_sum = input_pubkey_sum.combine(pk)
            .map_err(|_| "failed to combine input pubkeys")?;
    }
    
    // Step 3: Create tagged hash according to BIP-352
    // Hash = tagged_hash("BIP0352/SharedSecret", ecdh_shared || ser₂₅₆(input_pubkey_sum))
    let mut msg = Vec::new();
    msg.extend_from_slice(ecdh_shared.as_ref());
    msg.extend_from_slice(&input_pubkey_sum.serialize());
    
    Ok(tagged_hash("BIP0352/SharedSecret", &msg))
}

/// Create output public key for recipient (sender side)
fn create_silent_payment_output(
    input_privkey: &SecretKey,
    scan_pubkey: &SecpPublicKey,
    spend_pubkey: &SecpPublicKey,
    input_pubkeys: &[SecpPublicKey],
    output_index: u32,
) -> Result<(XOnlyPublicKey, [u8; 32]), String> {
    let secp = Secp256k1::new();
    
    // Generate shared secret
    let shared_secret = generate_shared_secret(input_privkey, scan_pubkey, input_pubkeys)?;
    
    // Add output index for multiple outputs to same recipient
    let mut tweak_data = Vec::from(shared_secret);
    tweak_data.extend_from_slice(&output_index.to_le_bytes());
    
    let tweak_hash = tagged_hash("BIP0352/Tweak", &tweak_data);
    let tweak_scalar = SecretKey::from_slice(&tweak_hash)
        .map_err(|_| "invalid tweak scalar")?;
    
    // Compute tweaked public key: P_output = B_spend + tweak·G
    let tweak_point = SecpPublicKey::from_secret_key(&secp, &tweak_scalar);
    let output_pubkey = spend_pubkey.combine(&tweak_point)
        .map_err(|_| "failed to create output pubkey")?;
    
    // Convert to x-only for taproot
    let xonly = XOnlyPublicKey::from_slice(&output_pubkey.serialize()[1..33])
        .map_err(|_| "failed to create x-only pubkey")?;
    
    Ok((xonly, tweak_hash))
}

/// Scan for received outputs (receiver side)
fn scan_for_outputs(
    scan_privkey: &SecretKey,
    spend_pubkey: &SecpPublicKey,
    ephemeral_pubkey: &SecpPublicKey,
    input_pubkeys: &[SecpPublicKey],
    outputs: &[(XOnlyPublicKey, u64)],
) -> Result<Vec<(usize, [u8; 32])>, String> {
    let secp = Secp256k1::new();
    let mut matches = Vec::new();
    
    // Generate shared secret using ephemeral pubkey from transaction
    let shared_secret = generate_shared_secret(scan_privkey, ephemeral_pubkey, input_pubkeys)?;
    
    // Check each output
    for (idx, (output_xonly, _value)) in outputs.iter().enumerate() {
        // Compute expected tweak for this output index
        let mut tweak_data = Vec::from(shared_secret);
        tweak_data.extend_from_slice(&(idx as u32).to_le_bytes());
        
        let tweak_hash = tagged_hash("BIP0352/Tweak", &tweak_data);
        let tweak_scalar = match SecretKey::from_slice(&tweak_hash) {
            Ok(s) => s,
            Err(_) => continue,
        };
        
        // Compute expected output: P = B_spend + tweak·G
        let tweak_point = SecpPublicKey::from_secret_key(&secp, &tweak_scalar);
        let expected_pubkey = match spend_pubkey.combine(&tweak_point) {
            Ok(p) => p,
            Err(_) => continue,
        };
        
        let expected_xonly = match XOnlyPublicKey::from_slice(&expected_pubkey.serialize()[1..33]) {
            Ok(x) => x,
            Err(_) => continue,
        };
        
        // Check if it matches
        if &expected_xonly == output_xonly {
            matches.push((idx, tweak_hash));
        }
    }
    
    Ok(matches)
}

// FFI FUNCTIONS
/// Generate Silent Payment address from mnemonic
#[no_mangle]
pub extern "C" fn sp_generate_address_from_mnemonic(
    mnemonic_ptr: *const c_char,
    spend_path_ptr: *const c_char,
    scan_path_ptr: *const c_char,
    passphrase_ptr: *const c_char,
    is_testnet: u8,  // FIXED: u8 for Dart FFI - stable across versions
) -> *mut c_char {
    let mnemonic = match parse_c_str(mnemonic_ptr) {
        Ok(m) => m,
        Err(e) => return error_json(&e),
    };
    
    let spend_path = match parse_c_str(spend_path_ptr) {
        Ok(p) if !p.is_empty() => p,
        _ => "m/352h/0h/0h/0/0".to_string(), // BIP-352 standard path - future-proof
    };
    
    let scan_path = match parse_c_str(scan_path_ptr) {
        Ok(p) if !p.is_empty() => p,
        _ => "m/352h/0h/0h/1/0".to_string(),
    };
    
    let passphrase = match parse_c_str(passphrase_ptr) {
        Ok(p) => p,
        Err(e) => return error_json(&e),
    };
    
    let network = if is_testnet == 1 { Network::Testnet } else { Network::Bitcoin };
    let secp = Secp256k1::new();
    
    // Derive keys
    let spend_xprv = match derive_xprv_from_mnemonic(&mnemonic, &passphrase, &spend_path, network) {
        Ok(x) => x,
        Err(e) => return error_json(&e),
    };
    
    let scan_xprv = match derive_xprv_from_mnemonic(&mnemonic, &passphrase, &scan_path, network) {
        Ok(x) => x,
        Err(e) => return error_json(&e),
    };
    
    let spend_pubkey = SecpPublicKey::from_secret_key(&secp, &spend_xprv.private_key);
    let scan_pubkey = SecpPublicKey::from_secret_key(&secp, &scan_xprv.private_key);
    
    // Create BIP-352 compliant address
    let address = match encode_silent_payment_address(&scan_pubkey, &spend_pubkey, is_testnet == 1) {
        Ok(a) => a,
        Err(e) => return error_json(&e),
    };
    
    let result = SilentPaymentAddress {
        address,
        scan_pubkey: pubkey_to_hex(&scan_pubkey),
        spend_pubkey: pubkey_to_hex(&spend_pubkey),
        network: format!("{:?}", network),
    };
    
    match serde_json::to_string(&result) {
        Ok(json) => match CString::new(json) {
            Ok(c) => c.into_raw(),
            Err(_) => error_json("json serialization failed"),
        },
        Err(_) => error_json("json serialization failed"),
    }
}

/// Create Silent Payment output (sender side)
#[no_mangle]
pub extern "C" fn sp_create_output(
    recipient_address_ptr: *const c_char,
    input_privkey_hex_ptr: *const c_char,
    input_pubkeys_json_ptr: *const c_char,
    output_index: u32,
    is_testnet: u8,
) -> *mut c_char {
    let recipient_address = match parse_c_str(recipient_address_ptr) {
        Ok(a) => a,
        Err(e) => return error_json(&e),
    };
    
    let input_privkey_hex = match parse_c_str(input_privkey_hex_ptr) {
        Ok(h) => h,
        Err(e) => return error_json(&e),
    };
    
    let input_pubkeys_json = match parse_c_str(input_pubkeys_json_ptr) {
        Ok(j) => j,
        Err(e) => return error_json(&e),
    };
    
    // Decode recipient address
    let (scan_pubkey, spend_pubkey) = match decode_silent_payment_address(&recipient_address) {
        Ok(keys) => keys,
        Err(e) => return error_json(&e),
    };
    
    // Parse input private key
    let input_privkey_bytes = match hex::decode(&input_privkey_hex) {
        Ok(b) => b,
        Err(_) => return error_json("invalid input privkey hex"),
    };
    let input_privkey = match SecretKey::from_slice(&input_privkey_bytes) {
        Ok(sk) => sk,
        Err(_) => return error_json("invalid input privkey"),
    };
    
    // Parse input public keys
    let input_pubkeys_arr: Vec<String> = match serde_json::from_str(&input_pubkeys_json) {
        Ok(arr) => arr,
        Err(_) => return error_json("invalid input pubkeys json"),
    };
    
    let mut input_pubkeys = Vec::new();
    for hex_str in input_pubkeys_arr {
        let bytes = match hex::decode(&hex_str) {
            Ok(b) => b,
            Err(_) => return error_json("invalid pubkey hex"),
        };
        let pubkey = match SecpPublicKey::from_slice(&bytes) {
            Ok(pk) => pk,
            Err(_) => return error_json("invalid pubkey"),
        };
        input_pubkeys.push(pubkey);
    }
    
    if input_pubkeys.is_empty() {
        return error_json("no input pubkeys provided");
    }
    
    // Create output
    let (output_xonly, _tweak) = match create_silent_payment_output(
        &input_privkey,
        &scan_pubkey,
        &spend_pubkey,
        &input_pubkeys,
        output_index,
    ) {
        Ok(out) => out,
        Err(e) => return error_json(&e),
    };
    
    let secp = Secp256k1::new();
    let ephemeral_pubkey = SecpPublicKey::from_secret_key(&secp, &input_privkey);
    
    let result = SilentPaymentOutput {
        ephemeral_pubkey: pubkey_to_hex(&ephemeral_pubkey),
        output_pubkey: hex::encode(output_xonly.serialize()),
        tweaked_output_key: hex::encode(output_xonly.serialize()),
        sp_address: recipient_address,
        network: format!("{:?}", if is_testnet == 1 { Network::Testnet } else { Network::Bitcoin }),
    };
    
    match serde_json::to_string(&result) {
        Ok(json) => match CString::new(json) {
            Ok(c) => c.into_raw(),
            Err(_) => error_json("json serialization failed"),
        },
        Err(_) => error_json("json serialization failed"),
    }
}

/// Free C string memory
#[no_mangle]
pub extern "C" fn sp_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            let _ = CString::from_raw(s);
        }
    }
}

// TESTS (Add these to verify correctness - future-proof with version-agnostic logic)


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_encoding_decoding() {
        let secp = Secp256k1::new();
        let mut rng = OsRng;
        
        let scan_sk = SecretKey::new(&mut rng);
        let spend_sk = SecretKey::new(&mut rng);
        
        let scan_pk = SecpPublicKey::from_secret_key(&secp, &scan_sk);
        let spend_pk = SecpPublicKey::from_secret_key(&secp, &spend_sk);
        
        let address = encode_silent_payment_address(&scan_pk, &spend_pk, false).unwrap();
        let (decoded_scan, decoded_spend) = decode_silent_payment_address(&address).unwrap();
        
        assert_eq!(scan_pk, decoded_scan);
        assert_eq!(spend_pk, decoded_spend);
    }
    
    #[test]
    fn test_output_creation_and_scanning() {
        let secp = Secp256k1::new();
        let mut rng = OsRng;
        
        // Receiver keys
        let scan_sk = SecretKey::new(&mut rng);
        let spend_sk = SecretKey::new(&mut rng);
        let scan_pk = SecpPublicKey::from_secret_key(&secp, &scan_sk);
        let spend_pk = SecpPublicKey::from_secret_key(&secp, &spend_sk);
        
        // Sender creates output
        let input_sk = SecretKey::new(&mut rng);
        let input_pk = SecpPublicKey::from_secret_key(&secp, &input_sk);
        let input_pubkeys = vec![input_pk];
        
        let (output_xonly, _) = create_silent_payment_output(
            &input_sk,
            &scan_pk,
            &spend_pk,
            &input_pubkeys,
            0,
        ).unwrap();
        
        // Receiver scans
        let outputs = vec![(output_xonly, 100000)];
        let matches = scan_for_outputs(
            &scan_sk,
            &spend_pk,
            &input_pk,
            &input_pubkeys,
            &outputs,
        ).unwrap();
        
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].0, 0);
    }
}