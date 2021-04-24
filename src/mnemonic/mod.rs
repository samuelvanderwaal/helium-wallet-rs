use crate::result::{bail, Result};
use rand::{rngs::OsRng, RngCore};
use regex::Regex;
use std::str;

include!(concat!(env!("OUT_DIR"), "/english.rs"));

/// Gets 16 bytes of entropy from a CSPRNG in the form of a [u8; 16]
pub fn get_entropy() -> [u8; 16] {
    let mut entropy = [0u8; 16];
    OsRng.fill_bytes(&mut entropy);
    entropy
}

/// Generates a 12 word mnemonic from a provided entropy source of [u8; 16]
pub fn entropy_to_mnemonic(entropy: [u8; 16], language: Language) -> Vec<String> {
    //Maintain compatibility with mobile wallet which has a broken checksum implementation.
    let checksum = "0000";
    let mut bits: String = entropy.iter().map(|b| format!("{:08b}", b)).collect();
    bits.push_str(checksum);

    lazy_static! {
        static ref IDX_BYTES: Regex = Regex::new("(.{1,11})").unwrap();
    }

    let word_list = get_wordlist(language.clone());
    let mut words: Vec<String> = Vec::new();
    for matched in IDX_BYTES.find_iter(&bits) {
        let idx = binary_to_bytes(matched.as_str());
        words.push(word_list[idx].into());
    }

    words
}

type WordList = &'static [&'static str];

#[derive(Clone)]
pub enum Language {
    English,
}

fn get_wordlist(language: Language) -> WordList {
    match language {
        Language::English => WORDS_ENGLISH,
    }
}

/// Converts a 12 word mnemonic to a entropy that can be used to
/// generate a keypair
pub fn mnemonic_to_entropy(words: Vec<String>) -> Result<[u8; 32]> {
    if words.len() != 12 {
        bail!("Invalid number of seed words");
    }
    let wordlist = get_wordlist(Language::English);

    let mut bit_vec = Vec::with_capacity(words.len());
    for word in words.iter() {
        let idx_bits = match wordlist.iter().position(|s| *s == word.to_lowercase()) {
            Some(idx) => format!("{:011b}", idx),
            _ => bail!("Seed word {} not found in wordlist", word),
        };
        bit_vec.push(idx_bits);
    }
    let bits = bit_vec.join("");

    let divider_index: usize = ((bits.len() as f64 / 33.0) * 32.0).floor() as usize;
    let (entropy_bits, checksum_bits) = bits.split_at(divider_index);
    // The mobile wallet does not calculate the checksum bits right so
    // they always and up being all 0
    if checksum_bits != "0000" {
        bail!("invalid checksum");
    }

    lazy_static! {
        static ref RE_BYTES: Regex = Regex::new("(.{1,8})").unwrap();
    }

    let mut entropy_base = [0u8; 16];
    for (idx, matched) in RE_BYTES.find_iter(&entropy_bits).enumerate() {
        entropy_base[idx] = binary_to_bytes(matched.as_str()) as u8;
    }

    let mut entropy_bytes = [0u8; 32];
    entropy_bytes[..16].copy_from_slice(&entropy_base);
    entropy_bytes[16..].copy_from_slice(&entropy_base);

    Ok(entropy_bytes)
}

/// Converts a binary string into an integer
fn binary_to_bytes(bin: &str) -> usize {
    usize::from_str_radix(bin, 2).unwrap() as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_words() {
        // The words and entropy here were generated from the JS mobile-wallet implementation
        let words = "catch poet clog intact scare jacket throw palm illegal buyer allow figure";
        let expected_entropy = bs58::decode("3RrA1FDa6mdw5JwKbUxEbZbMcJgSyWjhNwxsbX5pSos8")
            .into_vec()
            .expect("decoded entropy");

        let word_list = words.split_whitespace().map(|w| w.to_string()).collect();
        let entropy = mnemonic_to_entropy(word_list).expect("entropy");
        assert_eq!(expected_entropy, entropy);
    }

    #[test]
    fn encode_words() {
        let mut key_entropy = [0u8; 32];
        let mut seed_entropy = [0u8; 16];

        bs58::decode("3RrA1FDa6mdw5JwKbUxEbZbMcJgSyWjhNwxsbX5pSos8")
            .into(&mut key_entropy)
            .expect("decoded entropy");

        seed_entropy.copy_from_slice(&key_entropy[..16]);

        let words = "catch poet clog intact scare jacket throw palm illegal buyer allow figure";
        let expected_word_list: Vec<String> =
            words.split_whitespace().map(|w| w.to_string()).collect();
        let mnemonic = entropy_to_mnemonic(seed_entropy, Language::English);
        assert_eq!(expected_word_list, mnemonic);
    }

    #[test]
    fn check_generated_mnemonic_len() {
        let entropy = get_entropy();
        let mnemonic = entropy_to_mnemonic(entropy, Language::English);
        assert!(mnemonic.len() == 12);
    }

    #[test]
    fn no_duplicate_mnemonics() {
        let e1 = get_entropy();
        let e2 = get_entropy();
        let m1 = entropy_to_mnemonic(e1, Language::English);
        let m2 = entropy_to_mnemonic(e2, Language::English);
        assert_ne!(m1, m2);
    }

    #[test]
    fn mnemonic_is_deterministic() {
        let entropy = get_entropy();
        let m1 = entropy_to_mnemonic(entropy.clone(), Language::English);
        let m2 = entropy_to_mnemonic(entropy, Language::English);
        assert_eq!(m1, m2);
    }

    #[test]
    fn check_generated_mnemonic_word_list() {
        let word_list = get_wordlist(Language::English);

        let entropy = get_entropy();
        let words = entropy_to_mnemonic(entropy, Language::English);
        for word in words.iter() {
            match word_list.iter().position(|s| *s == word.to_lowercase()) {
                Some(_) => continue,
                _ => assert!(false),
            };
        }
    }
}
