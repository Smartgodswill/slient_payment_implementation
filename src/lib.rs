#![allow(clippy::unwrap_used)]

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use bitcoin::bip32::{DerivationPath, ExtendedPrivKey};
use bip39::{Language, Mnemonic};
use bitcoin::secp256k1::{
    ecdh::SharedSecret, PublicKey as SecpPublicKey, Secp256k1, SecretKey, XOnlyPublicKey,
};
use bitcoin::{Address, Network};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
    cstr.to_str()
        .map(|s| s.to_string())
        .map_err(|e| format!("invalid utf8: {}", e))
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
        .map_err(|e| format!("bad mnemonic: {}", e))?;
    let seed = mnemonic.to_seed(passphrase);
    let xprv =
        ExtendedPrivKey::new_master(network, &seed).map_err(|e| format!("master xprv: {}", e))?;
    let path = derivation_path
        .parse::<DerivationPath>()
        .map_err(|e| format!("bad derivation path: {}", e))?;
    let secp = Secp256k1::new();
    xprv.derive_priv(&secp, &path)
        .map_err(|e| format!("derive_priv: {}", e))
}

/// Receiver: derive spend & scan keys and compute a Taproot (P2TR) silent-payment address
#[no_mangle]
pub extern "C" fn sp_generate_silent_address_from_mnemonic(
    mnemonic_ptr: *const c_char,
    spend_path_ptr: *const c_char,
    scan_path_ptr: *const c_char,
    passphrase_ptr: *const c_char,
    is_testnet: bool,
) -> *mut c_char {
    let mnemonic = parse_c_str(mnemonic_ptr).unwrap_or_default();
    let spend_path = parse_c_str(spend_path_ptr).unwrap_or_else(|_| "m/86'/0'/0'/0/0".to_string());
    let scan_path = parse_c_str(scan_path_ptr).unwrap_or_else(|_| "m/86'/0'/0'/0/1".to_string());
    let passphrase = parse_c_str(passphrase_ptr).unwrap_or_default();

    let network = if is_testnet { Network::Testnet } else { Network::Bitcoin };
    let secp = Secp256k1::new();

    let spend_xprv = derive_xprv_from_mnemonic(&mnemonic, &passphrase, &spend_path, network)
        .unwrap();
    let scan_xprv = derive_xprv_from_mnemonic(&mnemonic, &passphrase, &scan_path, network)
        .unwrap();

    let spend_pub = SecpPublicKey::from_secret_key(&secp, &spend_xprv.private_key);
    let scan_pub = SecpPublicKey::from_secret_key(&secp, &scan_xprv.private_key);

    let mut rng = OsRng;
    let ephemeral_sk = SecretKey::new(&mut rng);
    let ephemeral_pk = SecpPublicKey::from_secret_key(&secp, &ephemeral_sk);

    let shared = SharedSecret::new(&scan_pub, &ephemeral_sk);
    let tweak_bytes = Sha256::digest(shared.as_ref());
    let tweak_sk = SecretKey::from_slice(&tweak_bytes).unwrap();
    let tweak_point = SecpPublicKey::from_secret_key(&secp, &tweak_sk);

    let combined = spend_pub.combine(&tweak_point).unwrap();
    let xonly = XOnlyPublicKey::from_slice(&combined.serialize()[1..33]).unwrap();
    let address = Address::p2tr(&secp, xonly, None, network);

    let result = SpAddress {
        sp_address: address.to_string(),
        internal_pubkey: pubkey_to_hex(&spend_pub),
        spend_pubkey: pubkey_to_hex(&combined),
        ephemeral_priv: sk_to_hex(&ephemeral_sk),
        ephemeral_pub: pubkey_to_hex(&ephemeral_pk),
        network: format!("{:?}", network),
    };

    CString::new(serde_json::to_string(&result).unwrap())
        .unwrap()
        .into_raw()
}

/// Sender: compute ephemeral keypair + output pubkey + address
#[no_mangle]
pub extern "C" fn sp_create_silent_output_from_pubkeys(
    spend_pub_hex_ptr: *const c_char,
    scan_pub_hex_ptr: *const c_char,
    is_testnet: bool,
) -> *mut c_char {
    let spend_pub_hex = parse_c_str(spend_pub_hex_ptr).unwrap_or_default();
    let scan_pub_hex = parse_c_str(scan_pub_hex_ptr).unwrap_or_default();

    let spend_pub_bytes = hex::decode(&spend_pub_hex).unwrap();
    let scan_pub_bytes = hex::decode(&scan_pub_hex).unwrap();

    let secp = Secp256k1::new();
    let spend_pub = SecpPublicKey::from_slice(&spend_pub_bytes).unwrap();
    let scan_pub = SecpPublicKey::from_slice(&scan_pub_bytes).unwrap();

    let mut rng = OsRng;
    let ephemeral_sk = SecretKey::new(&mut rng);
    let ephemeral_pk = SecpPublicKey::from_secret_key(&secp, &ephemeral_sk);

    let shared = SharedSecret::new(&scan_pub, &ephemeral_sk);
    let tweak_bytes = Sha256::digest(shared.as_ref());
    let tweak_sk = SecretKey::from_slice(&tweak_bytes).unwrap();
    let tweak_point = SecpPublicKey::from_secret_key(&secp, &tweak_sk);

    let combined = spend_pub.combine(&tweak_point).unwrap();
    let xonly = XOnlyPublicKey::from_slice(&combined.serialize()[1..33]).unwrap();

    let network = if is_testnet { Network::Testnet } else { Network::Bitcoin };
    let address = Address::p2tr(&secp, xonly, None, network);

    let result = SenderOutput {
        ephemeral_priv: sk_to_hex(&ephemeral_sk),
        ephemeral_pub: pubkey_to_hex(&ephemeral_pk),
        output_pubkey: pubkey_to_hex(&combined),
        sp_address: address.to_string(),
        network: format!("{:?}", network),
    };

    CString::new(serde_json::to_string(&result).unwrap())
        .unwrap()
        .into_raw()
}

/// Free string returned to FFI caller
#[no_mangle]
pub extern "C" fn sp_free_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        let _ = CString::from_raw(s);
    }
}
