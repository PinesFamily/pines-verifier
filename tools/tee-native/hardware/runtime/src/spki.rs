//! Exact canonical DER acceptance for the RSA-2048 SubjectPublicKeyInfo that an
//! attested AWS KMS `Recipient` requires. `RSAES_OAEP_SHA_256` is the only
//! documented recipient algorithm, so the only key form KMS can use here is an
//! RSA public key; this module refuses every other encoding without adding a
//! parser or a dependency to the measured image.
//! <https://docs.aws.amazon.com/kms/latest/APIReference/API_RecipientInfo.html>

/// SEQUENCE(290) · AlgorithmIdentifier(rsaEncryption, NULL) · BIT STRING(271,
/// 0 unused bits) · SEQUENCE(266) · INTEGER(257, leading zero) in definite-length
/// DER. A 2048-bit modulus and the 65537 exponent make every length fixed, so the
/// whole envelope is a constant and only the modulus itself is variable.
const RSA_2048_SPKI_PREFIX: [u8; 33] = [
    0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
    0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01,
    0x00,
];
const RSA_EXPONENT_65537: [u8; 5] = [0x02, 0x03, 0x01, 0x00, 0x01];
pub const RSA_2048_SPKI_LEN: usize = 294;
const MODULUS: std::ops::Range<usize> = 33..289;

pub fn is_rsa_2048_spki(bytes: &[u8]) -> bool {
    bytes.len() == RSA_2048_SPKI_LEN
        && bytes[..RSA_2048_SPKI_PREFIX.len()] == RSA_2048_SPKI_PREFIX
        && bytes[MODULUS.end..] == RSA_EXPONENT_65537
        // Exactly 2048 significant bits, and an RSA modulus is always odd.
        && bytes[MODULUS.start] & 0x80 != 0
        && bytes[MODULUS.end - 1] & 1 == 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};

    /// An actual RSA-2048 SubjectPublicKeyInfo exported by Node's
    /// `crypto` — the same call `kms/recipient.mjs` makes for a recipient key.
    /// Shared with `kms/issuer.test.mjs` so both implementations are shown to
    /// accept identical bytes. Synthetic test input: no enclave or KMS key uses
    /// it, and its private half was discarded at generation.
    const NODE_RECIPIENT_SPKI: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsVdo5srRYxUhw7LMlnmhhNB0UfRlQ98E1WOnpcvP0SUr4ZFVFEn8yTWWtm6zoGfWwT6G+PyBf71F03ZV6AVnDlj2Dvr8VeHdr39gpYS/gpNNOSleeLTsJigFQMwR+fx5F6ylHbqffWOASBSqV/RWwFEf311mIwXez8KbjwQ6K8PmKUt9jQG11bMHzk58lD14A0Ly9/73JiDdWXmn7o/A8s4SZA5N7Dth3LmGeKmsbzIRC4xc000zbFeXheyA7E6VqoV6MIvQ0+8Ql1cJxe2Ic8Jgsl7lYbPO26S5z2E8k3QnudvWtgk3jXvBCZlO9w1PqkleUZzqA3X2lkZPUiwX3QIDAQAB";

    #[test]
    fn accepts_a_real_node_generated_recipient_key() {
        let key = STANDARD.decode(NODE_RECIPIENT_SPKI).unwrap();
        assert_eq!(key.len(), RSA_2048_SPKI_LEN);
        assert!(is_rsa_2048_spki(&key));
    }

    // A structurally exact envelope with a synthetic modulus, used for the
    // negative cases so each refusal has exactly one changed byte.
    fn synthetic() -> Vec<u8> {
        let mut bytes = Vec::with_capacity(RSA_2048_SPKI_LEN);
        bytes.extend_from_slice(&RSA_2048_SPKI_PREFIX);
        for index in 0..256 {
            bytes.push(if index == 0 {
                0xc1
            } else if index == 255 {
                0x8d
            } else {
                (index as u8) ^ 0x5a
            });
        }
        bytes.extend_from_slice(&RSA_EXPONENT_65537);
        bytes
    }

    #[test]
    fn accepts_only_a_canonical_rsa_2048_spki() {
        let key = synthetic();
        assert_eq!(key.len(), RSA_2048_SPKI_LEN);
        assert!(is_rsa_2048_spki(&key));
    }

    #[test]
    fn refuses_other_lengths_including_the_existing_binding_sizes() {
        for length in [0usize, 32, 91, 293, 295, 550] {
            assert!(!is_rsa_2048_spki(&vec![0x30; length]));
        }
        assert!(!is_rsa_2048_spki(&synthetic()[..293]));
    }

    #[test]
    fn refuses_wrong_algorithm_exponent_or_non_rsa_modulus() {
        // An EC SPKI of the right length, a changed algorithm OID, a changed
        // length header, a short exponent, an even modulus and a modulus with a
        // clear high bit all fail, so arbitrary 294-byte input is not attestable.
        for (reason, index, value) in [
            ("id-ecPublicKey prefix", 8, 0x2b),
            ("NULL parameters replaced", 17, 0x30),
            ("non-canonical length", 1, 0x81),
            ("dropped INTEGER pad", 32, 0x01),
            ("exponent 3", 291, 0x03),
            ("2047-bit modulus", 33, 0x41),
            ("even modulus", 288, 0x8c),
            ("unused BIT STRING bits", 23, 0x01),
        ] {
            let mut key = synthetic();
            key[index] = value;
            assert!(!is_rsa_2048_spki(&key), "{reason}");
            assert_eq!(key.len(), RSA_2048_SPKI_LEN);
        }
    }
}
