use aes_soft::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use hex_literal::hex;
use sha2::{Digest, Sha256};
use std::panic;
use wasm_bindgen::prelude::*;

const SHA_SALT: &str = "vlkh3EOIfr";
const AES_IV: [u8; 16] = hex!("abcddeadbeefbcdaabcddeadbeefbcda");

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

#[wasm_bindgen(start)]
pub fn setup_hook() {
    panic::set_hook(Box::new(console_error_panic_hook::hook));
}

/// 지정된 문자열에 솔트를 적절히 추가한 후 해싱한 결과를 반환합니다.
pub(crate) fn generate_key(text: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.input(SHA_SALT);
    hasher.input(text);
    hasher.input(SHA_SALT);

    hasher.result().to_vec()
}

/// 지정된 입력 문자열을 AES-256-CBC 방식으로 암호화합니다.
#[wasm_bindgen]
pub fn encrypt(input: &str, passwd: &str) -> Vec<u8> {
    let key = generate_key(passwd);
    let cipher = Aes256Cbc::new_var(&key, &AES_IV).unwrap();
    cipher.encrypt_vec(input.as_bytes())
}

/// 지정된 암호문을 복호화합니다.
#[wasm_bindgen]
pub fn decrypt(input: &[u8], passwd: &str) -> Vec<u8> {
    let key = generate_key(passwd);
    let cipher = Aes256Cbc::new_var(&key, &AES_IV).unwrap();

    cipher.decrypt_vec(input).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen() {
        assert_eq!(
            &generate_key("hello")[..],
            &hex!("d70ca475de18784adef51c8e6106c2fd737a436b32ab78f9625ec02c9a8599b2")[..]
        );
    }

    #[test]
    fn key_consistency() {
        let key = generate_key("foo");
        for _ in 0..100 {
            let key_ = generate_key("foo");
            assert_eq!(key, key_);
        }
    }

    #[test]
    fn encdec_identity() {
        for (input, pass) in &[
            ("hello", "pass"),
            ("world", "pass1"),
            ("my", "bla"),
            ("name", "blah"),
        ] {
            assert_eq!(
                decrypt(&encrypt(input, pass), pass).as_slice(),
                input.as_bytes()
            );
        }
    }
}
