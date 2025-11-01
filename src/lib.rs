#![allow(clippy::unwrap_used)]

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::str::FromStr;

use bitcoin::psbt::Psbt;
use bitcoin::{absolute::LockTime, Address, Network, OutPoint, Transaction, TxIn, TxOut, Txid};
use bitcoin::{bech32, ScriptBuf};

use bech32::{encode, ToBase32, Variant};
use bip39::{Language, Mnemonic};
use bitcoin::bip32::{DerivationPath, ExtendedPrivKey};
use bitcoin::secp256k1::{
    ecdh::SharedSecret, PublicKey as SecpPublicKey, Secp256k1, SecretKey, XOnlyPublicKey,
};
use bitcoin::Sequence;
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

#[derive(Serialize, Deserialize)]
struct WalletKeys {
    spend_priv: String,
    scan_priv: String,
    spend_pub: String,
    scan_pub: String,
    network: String,
}

#[derive(Serialize, Deserialize)]
struct SilentTxResult {
    psbt_base64: String,
    raw_tx_hex: String,
    network: String,
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

/// BIP-style tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg)
fn tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    // compute tag hash once
    let tag_hash = Sha256::digest(tag.as_bytes());

    // new hasher: SHA256(tag_hash || tag_hash || msg)
    let mut hasher = Sha256::new();
    hasher.update(&tag_hash);
    hasher.update(&tag_hash);
    hasher.update(msg);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// Encode x-only pubkey as Silent Payments bech32m address ("sp" or "tsp")
fn encode_silent_address(xonly: &XOnlyPublicKey, is_testnet: bool) -> Result<String, String> {
    let hrp = if is_testnet { "tsp" } else { "sp" };
    encode(hrp, xonly.serialize().to_base32(), Variant::Bech32m)
        .map_err(|e| format!("bech32 encode failed: {}", e))
}

//////////////////// FFI Functions ////////////////////
//generate a silent address from a mnemonic.
#[no_mangle]
pub extern "C" fn sp_generate_silent_address_from_mnemonic(
    mnemonic_ptr: *const c_char,
    spend_path_ptr: *const c_char,
    scan_path_ptr: *const c_char,
    passphrase_ptr: *const c_char,
    is_testnet: bool,
) -> *mut c_char {
    // parse inputs
    let mnemonic = parse_c_str(mnemonic_ptr).unwrap_or_default();
    let spend_path = parse_c_str(spend_path_ptr).unwrap_or_else(|_| "m/86'/0'/0'/0/0".to_string());
    let scan_path = parse_c_str(scan_path_ptr).unwrap_or_else(|_| "m/86'/0'/0'/0/1".to_string());
    let passphrase = parse_c_str(passphrase_ptr).unwrap_or_default();

    let network = if is_testnet {
        Network::Testnet
    } else {
        Network::Bitcoin
    };
    let secp = Secp256k1::new();

    // derive spend and scan xprvs
    let spend_xprv =
        derive_xprv_from_mnemonic(&mnemonic, &passphrase, &spend_path, network).unwrap();
    let scan_xprv = derive_xprv_from_mnemonic(&mnemonic, &passphrase, &scan_path, network).unwrap();

    let spend_pub = SecpPublicKey::from_secret_key(&secp, &spend_xprv.private_key);
    let scan_pub = SecpPublicKey::from_secret_key(&secp, &scan_xprv.private_key);

    // ephemeral keypair
    let mut rng = OsRng;
    let ephemeral_sk = SecretKey::new(&mut rng);
    let ephemeral_pk = SecpPublicKey::from_secret_key(&secp, &ephemeral_sk);

    // shared secret and BIP352-tagged tweak
    let shared = SharedSecret::new(&scan_pub, &ephemeral_sk);
    // BIP352 tag per spec: "BIP352 Derive"
    let tweak_bytes = tagged_hash("BIP352 Derive", shared.as_ref());
    let tweak_sk = SecretKey::from_slice(&tweak_bytes).unwrap();
    let tweak_point = SecpPublicKey::from_secret_key(&secp, &tweak_sk);

    // combine and make x-only pubkey -> bech32m sp/tsp address
    let combined = spend_pub.combine(&tweak_point).unwrap();
    let xonly = XOnlyPublicKey::from_slice(&combined.serialize()[1..33]).unwrap();
    let address = encode_silent_address(&xonly, is_testnet).unwrap();

    let result = SpAddress {
        sp_address: address,
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

//Create output pubkey for sending to a given spend and scan pubkey.
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
    let tweak_bytes = tagged_hash("BIP352 Derive", shared.as_ref());
    let tweak_sk = SecretKey::from_slice(&tweak_bytes).unwrap();
    let tweak_point = SecpPublicKey::from_secret_key(&secp, &tweak_sk);

    let combined = spend_pub.combine(&tweak_point).unwrap();
    let xonly = XOnlyPublicKey::from_slice(&combined.serialize()[1..33]).unwrap();

    let address = encode_silent_address(&xonly, is_testnet).unwrap();

    let result = SenderOutput {
        ephemeral_priv: sk_to_hex(&ephemeral_sk),
        ephemeral_pub: pubkey_to_hex(&ephemeral_pk),
        output_pubkey: pubkey_to_hex(&combined),
        sp_address: address,
        network: format!(
            "{:?}",
            if is_testnet {
                Network::Testnet
            } else {
                Network::Bitcoin
            }
        ),
    };

    CString::new(serde_json::to_string(&result).unwrap())
        .unwrap()
        .into_raw()
}

//Scan a list of outputs and tell me which ones are mine.(i.e) Detect incoming SP payments
#[no_mangle]
pub extern "C" fn sp_scan_for_received_outputs(
    scan_priv_hex_ptr: *const c_char,
    spend_pub_hex_ptr: *const c_char,
    outputs_json_ptr: *const c_char,
) -> *mut c_char {
    let scan_priv_hex = parse_c_str(scan_priv_hex_ptr).unwrap_or_default();
    let spend_pub_hex = parse_c_str(spend_pub_hex_ptr).unwrap_or_default();
    let outputs_json = parse_c_str(outputs_json_ptr).unwrap_or_default();

    let secp = Secp256k1::new();
    let scan_priv_bytes = match hex::decode(&scan_priv_hex) {
        Ok(b) => b,
        Err(_) => {
            return CString::new("{\"error\":\"invalid scan_priv_hex\"}")
                .unwrap()
                .into_raw()
        }
    };
    let spend_pub_bytes = match hex::decode(&spend_pub_hex) {
        Ok(b) => b,
        Err(_) => {
            return CString::new("{\"error\":\"invalid spend_pub_hex\"}")
                .unwrap()
                .into_raw()
        }
    };

    let scan_priv = match SecretKey::from_slice(&scan_priv_bytes) {
        Ok(s) => s,
        Err(_) => {
            return CString::new("{\"error\":\"invalid scan_priv key\"}")
                .unwrap()
                .into_raw()
        }
    };
    let spend_pub = match SecpPublicKey::from_slice(&spend_pub_bytes) {
        Ok(p) => p,
        Err(_) => {
            return CString::new("{\"error\":\"invalid spend_pub key\"}")
                .unwrap()
                .into_raw()
        }
    };

    let outputs: Vec<serde_json::Value> = match serde_json::from_str(&outputs_json) {
        Ok(v) => v,
        Err(_) => {
            return CString::new("{\"error\":\"invalid outputs_json format\"}")
                .unwrap()
                .into_raw()
        }
    };

    let mut received = Vec::new();

    for output in outputs {
        if let (Some(ephemeral_hex), Some(output_hex)) = (
            output["ephemeral_pub"].as_str(),
            output["output_pubkey"].as_str(),
        ) {
            if let (Ok(ephemeral_bytes), Ok(output_bytes)) =
                (hex::decode(ephemeral_hex), hex::decode(output_hex))
            {
                if let Ok(ephemeral_pub) = SecpPublicKey::from_slice(&ephemeral_bytes) {
                    let shared = SharedSecret::new(&ephemeral_pub, &scan_priv);
                    let tweak_bytes = tagged_hash("BIP352 Derive", shared.as_ref());
                    let tweak_sk = match SecretKey::from_slice(&tweak_bytes) {
                        Ok(t) => t,
                        Err(_) => continue,
                    };
                    let tweak_point = SecpPublicKey::from_secret_key(&secp, &tweak_sk);
                    let combined = spend_pub.combine(&tweak_point).unwrap();
                    if <[u8; 33] as AsRef<[u8]>>::as_ref(&combined.serialize())
                        == output_bytes.as_slice()
                    {
                        received.push(output);
                    }
                }
            }
        }
    }

    CString::new(serde_json::to_string(&received).unwrap())
        .unwrap()
        .into_raw()
}

#[no_mangle]
pub extern "C" fn sp_export_keys(
    spend_priv_hex_ptr: *const c_char,
    scan_priv_hex_ptr: *const c_char,
    spend_pub_hex_ptr: *const c_char,
    scan_pub_hex_ptr: *const c_char,
    is_testnet: bool,
) -> *mut c_char {
    let spend_priv = parse_c_str(spend_priv_hex_ptr).unwrap_or_default();
    let scan_priv = parse_c_str(scan_priv_hex_ptr).unwrap_or_default();
    let spend_pub = parse_c_str(spend_pub_hex_ptr).unwrap_or_default();
    let scan_pub = parse_c_str(scan_pub_hex_ptr).unwrap_or_default();
    let network = if is_testnet { "Testnet" } else { "Bitcoin" }.to_string();

    let keys = WalletKeys {
        spend_priv,
        scan_priv,
        spend_pub,
        scan_pub,
        network,
    };

    CString::new(serde_json::to_string(&keys).unwrap())
        .unwrap()
        .into_raw()
}

#[no_mangle]
pub extern "C" fn sp_import_keys(keys_json_ptr: *const c_char) -> *mut c_char {
    let keys_json = parse_c_str(keys_json_ptr).unwrap_or_default();
    let keys: WalletKeys = match serde_json::from_str(&keys_json) {
        Ok(k) => k,
        Err(_) => {
            return CString::new("{\"error\":\"invalid keys json\"}")
                .unwrap()
                .into_raw()
        }
    };
    // For now we just return the parsed keys back to confirm successful import
    CString::new(serde_json::to_string(&keys).unwrap())
        .unwrap()
        .into_raw()
}

#[no_mangle]
pub extern "C" fn sp_construct_transaction(
    inputs_json_ptr: *const c_char,
    outputs_json_ptr: *const c_char,
    fee_sat: u64,
    is_testnet: bool,
) -> *mut c_char {
    use bitcoin::{
        absolute::LockTime, consensus::encode::serialize, psbt::PartiallySignedTransaction as Psbt,
        script::Script, witness::Witness, Address, Network, OutPoint, Transaction, TxIn, TxOut,
        Txid,
    };
    use std::{ffi::CString, str::FromStr};

    // Convert C strings
    let inputs_json = parse_c_str(inputs_json_ptr).unwrap_or_default();
    let outputs_json = parse_c_str(outputs_json_ptr).unwrap_or_default();

    let inputs: Vec<serde_json::Value> = match serde_json::from_str(&inputs_json) {
        Ok(v) => v,
        Err(_) => {
            return CString::new("{\"error\":\"invalid inputs json\"}")
                .unwrap()
                .into_raw()
        }
    };
    let outputs: Vec<serde_json::Value> = match serde_json::from_str(&outputs_json) {
        Ok(v) => v,
        Err(_) => {
            return CString::new("{\"error\":\"invalid outputs json\"}")
                .unwrap()
                .into_raw()
        }
    };

    let network = if is_testnet {
        Network::Testnet
    } else {
        Network::Bitcoin
    };
    let mut tx_ins = Vec::with_capacity(inputs.len());
    let mut tx_outs = Vec::with_capacity(outputs.len());

    // Build transaction inputs
    for input in inputs {
        let txid_str = match input["txid"].as_str() {
            Some(s) => s,
            None => continue,
        };
        let txid = match Txid::from_str(txid_str) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let vout = input["vout"].as_u64().unwrap_or(0) as u32;

        tx_ins.push(TxIn {
            previous_output: OutPoint { txid, vout },
            script_sig: ScriptBuf::new(),   // empty script
            sequence: Sequence(0xFFFFFFFF), // wrap in Sequence
            witness: Witness::default(),    // empty witness
        });
    }

    // Build transaction outputs
    for output in outputs {
        let addr_str = match output["address"].as_str() {
            Some(a) => a,
            None => continue,
        };
        let value = output["value"].as_u64().unwrap_or(0);

        let addr = match Address::from_str(addr_str) {
            Ok(a) => match a.require_network(network) {
                Ok(valid) => valid,
                Err(_) => continue,
            },
            Err(_) => continue,
        };

        tx_outs.push(TxOut {
            value,
            script_pubkey: addr.script_pubkey(),
        });
    }

    if tx_ins.is_empty() || tx_outs.is_empty() {
        return CString::new("{\"error\":\"no valid inputs or outputs\"}")
            .unwrap()
            .into_raw();
    }

    // Build transaction
    let tx = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: tx_ins,
        output: tx_outs,
    };

    // Serialize raw transaction
    let raw_tx_hex = hex::encode(serialize(&tx));

    // Wrap in PSBT
    let psbt = match Psbt::from_unsigned_tx(tx) {
        Ok(p) => p,
        Err(_) => {
            return CString::new("{\"error\":\"failed to create PSBT\"}")
                .unwrap()
                .into_raw()
        }
    };
    let psbt_base64 = psbt.to_string();

    #[derive(serde::Serialize)]
    struct SilentTxResult {
        psbt_base64: String,
        raw_tx_hex: String,
        network: String,
    }

    let result = SilentTxResult {
        psbt_base64,
        raw_tx_hex,
        network: format!("{:?}", network),
    };

    CString::new(serde_json::to_string(&result).unwrap())
        .unwrap()
        .into_raw()
}

#[no_mangle]
pub extern "C" fn sp_sign_psbt(
    psbt_base64_ptr: *const c_char,
    spend_priv_hex_ptr: *const c_char,
    ephemeral_priv_hex_ptr: *const c_char,
    scan_pub_hex_ptr: *const c_char,
) -> *mut c_char {
    use bitcoin::consensus::encode::serialize;
    use bitcoin::ecdsa::Signature as BitcoinSig;
    use bitcoin::hashes::{sha256, Hash};
    use bitcoin::psbt::PartiallySignedTransaction as Psbt;
    use bitcoin::secp256k1::ecdh::SharedSecret;
    use bitcoin::secp256k1::Scalar;
    use bitcoin::secp256k1::{PublicKey as SecpPublicKey, Secp256k1, SecretKey};
    use bitcoin::sighash::{EcdsaSighashType, SighashCache};
    use bitcoin::PublicKey;
    use std::ffi::CString;

    let psbt_base64 = parse_c_str(psbt_base64_ptr).unwrap_or_default();
    let spend_priv_hex = parse_c_str(spend_priv_hex_ptr).unwrap_or_default();
    let ephemeral_priv_hex = parse_c_str(ephemeral_priv_hex_ptr).unwrap_or_default();
    let scan_pub_hex = parse_c_str(scan_pub_hex_ptr).unwrap_or_default();

    let secp = Secp256k1::new();

    let mut psbt: Psbt = match psbt_base64.parse() {
        Ok(p) => p,
        Err(_) => {
            return CString::new("{\"error\":\"invalid PSBT\"}")
                .unwrap()
                .into_raw()
        }
    };

    let spend_sk = match SecretKey::from_slice(&hex::decode(&spend_priv_hex).unwrap_or_default()) {
        Ok(sk) => sk,
        Err(_) => {
            return CString::new("{\"error\":\"invalid spend priv\"}")
                .unwrap()
                .into_raw()
        }
    };
    let ephemeral_sk =
        match SecretKey::from_slice(&hex::decode(&ephemeral_priv_hex).unwrap_or_default()) {
            Ok(sk) => sk,
            Err(_) => {
                return CString::new("{\"error\":\"invalid ephemeral priv\"}")
                    .unwrap()
                    .into_raw()
            }
        };
    let scan_pub_bytes = match hex::decode(&scan_pub_hex) {
        Ok(b) => b,
        Err(_) => {
            return CString::new("{\"error\":\"invalid scan pub\"}")
                .unwrap()
                .into_raw()
        }
    };
    let scan_pub = match SecpPublicKey::from_slice(&scan_pub_bytes) {
        Ok(p) => p,
        Err(_) => {
            return CString::new("{\"error\":\"invalid scan pub key\"}")
                .unwrap()
                .into_raw()
        }
    };

    for (idx, input) in psbt.inputs.iter_mut().enumerate() {
        let witness_utxo = match &input.witness_utxo {
            Some(u) => u,
            None => continue,
        };

        let shared = SharedSecret::new(&scan_pub, &ephemeral_sk);
        let tweak_hash = sha256::Hash::hash(shared.as_ref());

        // Copy hash into a 32-byte array
        let mut tweak_array = [0u8; 32];
        tweak_array.copy_from_slice(tweak_hash.as_ref());

        // Convert array into Scalar
        let tweak_scalar = Scalar::from_be_bytes(tweak_array).expect("32-byte tweak is valid");

        // Apply tweak to spend key
        let mut combined_sk = spend_sk.clone();
        combined_sk.add_tweak(&tweak_scalar).unwrap();

        let combined_pk = SecpPublicKey::from_secret_key(&secp, &combined_sk);

        let sighash = SighashCache::new(&psbt.unsigned_tx)
            .segwit_signature_hash(
                idx,
                &witness_utxo.script_pubkey,
                witness_utxo.value,
                EcdsaSighashType::All,
            )
            .unwrap();
        let msg = bitcoin::secp256k1::Message::from_slice(&sighash[..]).unwrap();

        let sig = secp.sign_ecdsa(&msg, &combined_sk);

        // Convert to bitcoin::ecdsa::Signature
        let mut sig_bytes = sig.serialize_der().to_vec();
        sig_bytes.push(0x01); // SIGHASH_ALL
        let sig_bitcoin = BitcoinSig::from_slice(&sig_bytes).expect("valid signature");

        input
            .partial_sigs
            .insert(PublicKey::new(combined_pk), sig_bitcoin);
    }

    // Finalize **all** inputs after signing
    let raw_tx = hex::encode(serialize(&psbt.clone().extract_tx()));
    let result_json = serde_json::json!({
        "psbt_base64": psbt.to_string(),
        "raw_tx_hex": raw_tx
    });

    return CString::new(result_json.to_string()).unwrap().into_raw();
}

#[no_mangle]
pub extern "C" fn sp_free_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        let _ = CString::from_raw(s);
    }
}
