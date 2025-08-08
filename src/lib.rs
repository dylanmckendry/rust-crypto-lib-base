use std::ffi::{c_char, CStr, CString};
use hex;
use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use starknet::{core::crypto::ecdsa_sign, providers::sequencer::models::ContractAddresses};
use starknet_crypto::Felt;
use std::str::FromStr;

use crate::starknet_messages::{
    AssetId, OffChainMessage, Order, PositionId, StarknetDomain, Timestamp, TransferArgs,
};
pub mod starknet_messages;

pub struct StarkSignature {
    pub r: Felt,
    pub s: Felt,
    pub v: Felt,
}

#[repr(C)]
pub struct StarknetSign {
    r: *mut c_char,
    s: *mut c_char,
    v: *mut c_char,
}

fn grind_key(key_seed: BigUint) -> BigUint {
    let two_256 = BigUint::from_str(
        "115792089237316195423570985008687907853269984665640564039457584007913129639936",
    )
    .unwrap();
    let key_value_limit = BigUint::from_str(
        "3618502788666131213697322783095070105526743751716087489154079457884512865583",
    )
    .unwrap();

    let max_allowed_value = two_256.clone() - (two_256.clone() % (&key_value_limit));
    let mut index = BigUint::ZERO;
    loop {
        let hash_input = {
            let mut input = Vec::new();
            input.extend_from_slice(&key_seed.to_bytes_be());
            input.extend_from_slice(&index.to_bytes_be());
            input
        };
        let hash_result = Sha256::digest(&hash_input);
        let hash = hash_result.as_slice();
        let key = BigUint::from_bytes_be(&hash);

        if key < max_allowed_value {
            return key % (&key_value_limit);
        }

        index += BigUint::from_str("1").unwrap();
    }
}

pub fn get_private_key_from_eth_signature(signature: &str) -> Result<Felt, String> {
    let eth_sig_truncated = signature.trim_start_matches("0x");
    if eth_sig_truncated.len() < 64 {
        return Err("Invalid signature length".to_string());
    }
    let r = &eth_sig_truncated[..64];
    let r_bytes = hex::decode(r).map_err(|e| format!("Failed to decode r as hex: {:?}", e))?;
    let r_int = BigUint::from_bytes_be(&r_bytes);

    let ground_key = grind_key(r_int);
    return Ok(Felt::from_hex(&ground_key.to_str_radix(16)).unwrap());
}

pub fn sign_message(message: &Felt, private_key: &Felt) -> Result<StarkSignature, String> {
    return ecdsa_sign(private_key, &message)
        .map(|extended_signature| StarkSignature {
            r: extended_signature.r,
            s: extended_signature.s,
            v: extended_signature.v,
        })
        .map_err(|e| format!("Failed to sign message: {:?}", e));
}

#[no_mangle]
pub extern "C" fn starknet_sign(message: *const c_char, private_key: *const c_char) -> StarknetSign {
    let message = Felt::from_hex(unsafe { c_char_to_str(message) }.unwrap()).unwrap();
    let private_key = Felt::from_hex(unsafe { c_char_to_str(private_key) }.unwrap()).unwrap();

    let sign =  ecdsa_sign(&private_key, &message)
        .map(|extended_signature| StarkSignature {
            r: extended_signature.r,
            s: extended_signature.s,
            v: extended_signature.v,
        })
        .unwrap();

    let r = CString::new(sign.r.to_fixed_hex_string()).unwrap();
    let s = CString::new(sign.s.to_fixed_hex_string()).unwrap();
    let v = CString::new(sign.v.to_fixed_hex_string()).unwrap();

    StarknetSign {
        r: r.into_raw(),
        s: s.into_raw(),
        v: v.into_raw(),
    }
}


unsafe fn c_char_to_str<'a>(p: *const c_char) -> Result<&'a str, &'static str> {
    if p.is_null() {
        return Err("received null pointer");
    }
    CStr::from_ptr(p)
        .to_str()
        .map_err(|_| "parameter is not valid UTF‑8")
}

#[no_mangle]
pub extern "C" fn get_order_hash(
    position_id: u32,
    base_asset_id_hex: *const c_char,
    base_amount: i64,
    quote_asset_id_hex: *const c_char,
    quote_amount: i64,
    fee_asset_id_hex: *const c_char,
    fee_amount: u64,
    expiration: u64,
    salt: u64,
    user_public_key_hex: *const c_char,
    domain_chain_id: *const c_char,
) -> *mut c_char {

    let base_asset_id = Felt::from_hex(unsafe { c_char_to_str(base_asset_id_hex) }.unwrap()).unwrap();
    let quote_asset_id = Felt::from_hex(unsafe { c_char_to_str(quote_asset_id_hex) }.unwrap()).unwrap();
    let fee_asset_id = Felt::from_hex(unsafe { c_char_to_str(fee_asset_id_hex) }.unwrap()).unwrap();
    let user_key = Felt::from_hex(unsafe { c_char_to_str(user_public_key_hex) }.unwrap()).unwrap();

    let domain_name = "Perpetuals";
    let domain_version = "v0";
    let domain_chain_id = unsafe { c_char_to_str(domain_chain_id) }.unwrap();
    let revision: u32 = 1;

    let order = Order {
        position_id: PositionId { value: position_id },
        base_asset_id: AssetId {
            value: base_asset_id,
        },
        base_amount,
        quote_asset_id: AssetId {
            value: quote_asset_id,
        },
        quote_amount,
        fee_asset_id: AssetId {
            value: fee_asset_id,
        },
        fee_amount,
        expiration: Timestamp {
            seconds: expiration,
        },
        salt: salt
            .try_into()
            .unwrap(),
    };
    let domain = StarknetDomain {
        name: domain_name.to_string(),
        version: domain_version.to_string(),
        chain_id: domain_chain_id.to_string(),
        revision,
    };

    CString::new(order
        .message_hash(&domain, user_key)
        .unwrap()
        .to_hex_string()).unwrap().into_raw()
}

#[no_mangle]
pub unsafe extern "C" fn free_c_string_1(str1: *mut c_char) {
    unsafe { let _ = CString::from_raw(str1); };
}

#[no_mangle]
pub unsafe extern "C" fn free_c_string_2(str1: *mut c_char, str2: *mut c_char) {
    unsafe { let _ = CString::from_raw(str1); };
    unsafe { let _ = CString::from_raw(str2); };
}

#[no_mangle]
pub unsafe extern "C" fn free_c_string_3(str1: *mut c_char, str2: *mut c_char, str3: *mut c_char) {
    unsafe { let _ = CString::from_raw(str1); };
    unsafe { let _ = CString::from_raw(str2); };
    unsafe { let _ = CString::from_raw(str3); };
}