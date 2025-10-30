// src/lib.rs
#![allow(clippy::unwrap_used)]

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey};
use bitcoin::util::bip39::{Mnemonic, Language, Seed};
use bitcoin::{Network, Address, PrivateKey as BtcPrivateKey};
use bitcoin::secp256k1::{Secp256k1, SecretKey, PublicKey as SecpPublicKey, ecdh::SharedSecret, XOnlyPublicKey};
use rand::rngs::OsRng;
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};

#[derive(Serialize, Deserialize)]
struct SpAddress {
    sp_address: String,
    internal_pubkey: String,
    spend_pubkey: String,
    ephemeral_priv: String,
    ephemeral_pub: String,
    network: String,
}

#[derive(Serialize, Deserialize)]
struct SenderOutput {
    ephemeral_priv: String,
    ephemeral_pub: String,
    output_pubkey: String,
    sp_address: String,
    network: String,
}

/// Helper: parse C string, or return Err
fn parse_c_str(ptr: *const c_char) -> Result<String, String> {
    if ptr.is_null() {
        return Err("null pointer".into());
    }
    let cstr = unsafe { CStr::from_ptr(ptr) };
    cstr.to_str().map(|s| s.to_string()).map_err(|e| format!("invalid utf8: {}", e))
}

/// Convert secp public key to hex (compressed)
fn pubkey_to_hex(pk: &SecpPublicKey) -> String {
    hex::encode(pk.serialize())
}

/// Convert secret key to hex
fn sk_to_hex(sk: &SecretKey) -> String {
    hex::encode(sk.secret_bytes())
}

/// Derive extended private key for a given derivation path string (like "m/86'/0'/0'/0/0")
fn derive_xprv_from_mnemonic(
    mnemonic_str: &str,
    passphrase: &str,
    derivation_path: &str,
    network: Network,
) -> Result<ExtendedPrivKey, String> {
    let mnemonic = Mnemonic::from_phrase(mnemonic_str, Language::English)
        .map_err(|e| format!("bad mnemonic: {}", e))?;
    let seed = Seed::new(&mnemonic, passphrase);
    let xprv = ExtendedPrivKey::new_master(network, seed.as_bytes())
        .map_err(|e| format!("master xprv: {}", e))?;
    let path = derivation_path.parse::<DerivationPath>()
        .map_err(|e| format!("bad derivation path: {}", e))?;
    let secp = Secp256k1::new();
    let derived = xprv.derive_priv(&secp, &path)
        .map_err(|e| format!("derive_priv: {}", e))?;
    Ok(derived)
}

/// Receiver: derive spend & scan keys from mnemonic and compute a taproot (P2TR) silent-payment address.
/// Exported for FFI.
///
/// Params (all C strings):
/// - mnemonic_ptr: BIP39 phrase
/// - spend_path_ptr: derivation path for spend key (e.g. "m/86'/1'/0'/0/0")
/// - scan_path_ptr: derivation path for scan key  (e.g. "m/86'/1'/0'/0/1")
/// - passphrase_ptr: optional BIP39 passphrase (empty string if none)
/// - is_testnet: bool (true => testnet)
///
/// Returns: JSON string (caller must call sp_free_string)
#[no_mangle]
pub extern "C" fn sp_generate_silent_address_from_mnemonic(
    mnemonic_ptr: *const c_char,
    spend_path_ptr: *const c_char,
    scan_path_ptr: *const c_char,
    passphrase_ptr: *const c_char,
    is_testnet: bool,
) -> *mut c_char {
    // parse inputs
    let mnemonic = match parse_c_str(mnemonic_ptr) {
        Ok(s) => s,
        Err(e) => {
            let s = CString::new(format!("{{\"error\":\"{}\"}}", e)).unwrap();
            return s.into_raw();
        }
    };
    let spend_path = parse_c_str(spend_path_ptr).unwrap_or_else(|_| "m/86'/0'/0'/0/0".to_string());
    let scan_path = parse_c_str(scan_path_ptr).unwrap_or_else(|_| "m/86'/0'/0'/0/1".to_string());
    let passphrase = parse_c_str(passphrase_ptr).unwrap_or_else(|_| "".to_string());

    let network = if is_testnet { Network::Testnet } else { Network::Bitcoin };
    let secp = Secp256k1::new();

    // derive xprvs
    let spend_xprv = match derive_xprv_from_mnemonic(&mnemonic, &passphrase, &spend_path, network) {
        Ok(x) => x,
        Err(e) => {
            let s = CString::new(format!("{{\"error\":\"{}\"}}", e)).unwrap();
            return s.into_raw();
        }
    };
    let scan_xprv = match derive_xprv_from_mnemonic(&mnemonic, &passphrase, &scan_path, network) {
        Ok(x) => x,
        Err(e) => {
            let s = CString::new(format!("{{\"error\":\"{}\"}}", e)).unwrap();
            return s.into_raw();
        }
    };

    // get bitcoin::PrivateKey from ExtendedPrivKey
    let spend_priv_btc: BtcPrivateKey = spend_xprv.private_key;
    let scan_priv_btc: BtcPrivateKey = scan_xprv.private_key;

    // convert to secp secret keys and public keys
    let spend_priv_secp = match SecretKey::from_slice(&spend_priv_btc.inner_secret_bytes()) {
        Ok(sk) => sk,
        Err(e) => {
            let s = CString::new(format!("{{\"error\":\"invalid spend sk: {}\"}}", e)).unwrap();
            return s.into_raw();
        }
    };
    let scan_priv_secp = match SecretKey::from_slice(&scan_priv_btc.inner_secret_bytes()) {
        Ok(sk) => sk,
        Err(e) => {
            let s = CString::new(format!("{{\"error\":\"invalid scan sk: {}\"}}", e)).unwrap();
            return s.into_raw();
        }
    };

    let spend_pub = SecpPublicKey::from_secret_key(&secp, &spend_priv_secp);
    let scan_pub = SecpPublicKey::from_secret_key(&secp, &scan_priv_secp);

    // generate ephemeral keypair (for testing/receiver we expose ephemeral for debug; don't do that in prod)
    let mut rng = OsRng;
    let ephemeral_sk = SecretKey::new(&mut rng);
    let ephemeral_pk = SecpPublicKey::from_secret_key(&secp, &ephemeral_sk);

    // ECDH: shared = ephemeral_sk * scan_pub
    let shared = SharedSecret::new(&scan_pub, &ephemeral_sk);

    // tweak = SHA256(shared)
    let mut hasher = Sha256::new();
    hasher.update(shared.as_ref());
    let tweak_bytes = hasher.finalize();

    let tweak_sk = match SecretKey::from_slice(&tweak_bytes) {
        Ok(k) => k,
        Err(_) => {
            let s = CString::new(format!("{{\"error\":\"invalid tweak from ecdh\"}}")).unwrap();
            return s.into_raw();
        }
    };
    let tweak_point = SecpPublicKey::from_secret_key(&secp, &tweak_sk);

    // combined = spend_pub + tweak_point
    let combined = match SecpPublicKey::combine(&[spend_pub, tweak_point]) {
        Ok(pk) => pk,
        Err(e) => {
            let s = CString::new(format!("{{\"error\":\"combine failed: {}\"}}", e)).unwrap();
            return s.into_raw();
        }
    };

    // convert to xonly
    let (xonly, _parity) = match XOnlyPublicKey::from_pubkey(&combined) {
        Ok(v) => v,
        Err(e) => {
            let s = CString::new(format!("{{\"error\":\"xonly conversion failed: {}\"}}", e)).unwrap();
            return s.into_raw();
        }
    };

    // build address
    let address = Address::p2tr(&secp, xonly, network);
    let addr_str = address.to_string();

    let result = SpAddress {
        sp_address: addr_str,
        internal_pubkey: pubkey_to_hex(&spend_pub),
        spend_pubkey: pubkey_to_hex(&combined),
        ephemeral_priv: sk_to_hex(&ephemeral_sk),
        ephemeral_pub: pubkey_to_hex(&ephemeral_pk),
        network: format!("{:?}", network),
    };

    let json_str = match serde_json::to_string(&result) {
        Ok(s) => s,
        Err(e) => format!("{{\"error\":\"serde_json failed: {}\"}}", e),
    };

    CString::new(json_str).unwrap().into_raw()
}

/// Sender: given receiver's spend_pub and scan_pub (hex compressed),
/// compute ephemeral keypair and the actual output pubkey + address the sender should create.
///
/// Params:
/// - spend_pub_hex_ptr: C string hex compressed (02... or 03...)
/// - scan_pub_hex_ptr: C string hex compressed
/// - is_testnet: bool
///
/// Returns JSON (ephemeral_priv, ephemeral_pub, output_pubkey, sp_address, network).
#[no_mangle]
pub extern "C" fn sp_create_silent_output_from_pubkeys(
    spend_pub_hex_ptr: *const c_char,
    scan_pub_hex_ptr: *const c_char,
    is_testnet: bool,
) -> *mut c_char {
    let spend_pub_hex = match parse_c_str(spend_pub_hex_ptr) {
        Ok(s) => s,
        Err(e) => {
            let s = CString::new(format!("{{\"error\":\"{}\"}}", e)).unwrap();
            return s.into_raw();
        }
    };
    let scan_pub_hex = match parse_c_str(scan_pub_hex_ptr) {
        Ok(s) => s,
        Err(e) => {
            let s = CString::new(format!("{{\"error\":\"{}\"}}", e)).unwrap();
            return s.into_raw();
        }
    };

    // parse hex -> bytes -> secp public keys
    let spend_pub_bytes = match hex::decode(&spend_pub_hex) {
        Ok(b) => b,
        Err(e) => {
            let s = CString::new(format!("{{\"error\":\"bad spend_pub hex: {}\"}}", e)).unwrap();
            return s.into_raw();
        }
    };
    let scan_pub_bytes = match hex::decode(&scan_pub_hex) {
        Ok(b) => b,
        Err(e) => {
            let s = CString::new(format!("{{\"error\":\"bad scan_pub hex: {}\"}}", e)).unwrap();
            return s.into_raw();
        }
    };

    let secp = Secp256k1::new();
    let spend_pub = match SecpPublicKey::from_slice(&spend_pub_bytes) {
        Ok(pk) => pk,
        Err(e) => {
            let s = CString::new(format!("{{\"error\":\"invalid spend_pub: {}\"}}", e)).unwrap();
            return s.into_raw();
        }
    };
    let scan_pub = match SecpPublicKey::from_slice(&scan_pub_bytes) {
        Ok(pk) => pk,
        Err(e) => {
            let s = CString::new(format!("{{\"error\":\"invalid scan_pub: {}\"}}", e)).unwrap();
            return s.into_raw();
        }
    };

    // ephemeral keypair
    let mut rng = OsRng;
    let ephemeral_sk = SecretKey::new(&mut rng);
    let ephemeral_pk = SecpPublicKey::from_secret_key(&secp, &ephemeral_sk);

    // ecdh = ephemeral_sk * scan_pub
    let shared = SharedSecret::new(&scan_pub, &ephemeral_sk);

    // tweak = sha256(shared)
    let mut hasher = Sha256::new();
    hasher.update(shared.as_ref());
    let tweak_bytes = hasher.finalize();

    let tweak_sk = match SecretKey::from_slice(&tweak_bytes) {
        Ok(k) => k,
        Err(_) => {
            let s = CString::new(format!("{{\"error\":\"invalid tweak from ecdh\"}}")).unwrap();
            return s.into_raw();
        }
    };
    let tweak_point = SecpPublicKey::from_secret_key(&secp, &tweak_sk);

    // combined = spend_pub + tweak_point
    let combined = match SecpPublicKey::combine(&[spend_pub, tweak_point]) {
        Ok(pk) => pk,
        Err(e) => {
            let s = CString::new(format!("{{\"error\":\"combine failed: {}\"}}", e)).unwrap();
            return s.into_raw();
        }
    };

    // xonly
    let (xonly, _parity) = match XOnlyPublicKey::from_pubkey(&combined) {
        Ok(v) => v,
        Err(e) => {
            let s = CString::new(format!("{{\"error\":\"xonly conversion failed: {}\"}}", e)).unwrap();
            return s.into_raw();
        }
    };

    let network = if is_testnet { Network::Testnet } else { Network::Bitcoin };
    let address = Address::p2tr(&secp, xonly, network);

    let result = SenderOutput {
        ephemeral_priv: sk_to_hex(&ephemeral_sk),
        ephemeral_pub: pubkey_to_hex(&ephemeral_pk),
        output_pubkey: pubkey_to_hex(&combined),
        sp_address: address.to_string(),
        network: format!("{:?}", network),
    };

    let json = match serde_json::to_string(&result) {
        Ok(s) => s,
        Err(e) => format!("{{\"error\":\"serde_json failed: {}\"}}", e),
    };
    CString::new(json).unwrap().into_raw()
}

/// Free string returned to FFI caller
#[no_mangle]
pub extern "C" fn sp_free_string(s: *mut c_char) {
    if s.is_null() { return; }
    unsafe { let _ = CString::from_raw(s); }
}
