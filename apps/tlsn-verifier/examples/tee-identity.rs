//! Enclave-only, bounded stdin/stdout key holder. No plaintext key output, files,
//! network, logging, or export operation. The caller parses the public CMS
//! envelope; this process independently fixes all sizes and cipher parameters.
use base64::{engine::general_purpose::STANDARD, Engine};
use openssl::{encrypt::Decrypter, hash::MessageDigest, pkey::{PKey, Private}, rsa::{Padding, Rsa},
    sign::Signer, symm::{Cipher, Crypter, Mode}};
use serde::Deserialize;
use std::io::{self, BufRead, Read, Write};
use zeroize::Zeroizing;

const MAX_LINE: usize = 90_000;
const DOMAIN: &[u8] = b"pines/keyed-identity/v2\0";
type Result<T> = std::result::Result<T, ()>;

// A dedicated locked, non-dumpable page, explicitly wiped before munmap. This
// controls our copies; OpenSSL also makes short-lived internal crypto copies.
struct Secret { ptr: *mut u8, page: usize }
impl Secret {
    fn new(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 { return Err(()); }
        unsafe {
            let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
            if page < 4096 { return Err(()); }
            let ptr = libc::mmap(std::ptr::null_mut(), page, libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0);
            if ptr == libc::MAP_FAILED { return Err(()); }
            if libc::mlock(ptr, page) != 0 || libc::madvise(ptr, page, libc::MADV_DONTDUMP) != 0 {
                libc::munmap(ptr, page); return Err(());
            }
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr.cast(), 32);
            Ok(Self { ptr: ptr.cast(), page })
        }
    }
    fn bytes(&self) -> &[u8] { unsafe { std::slice::from_raw_parts(self.ptr, 32) } }
}
impl Drop for Secret {
    fn drop(&mut self) { unsafe {
        for i in 0..self.page { std::ptr::write_volatile(self.ptr.add(i), 0); }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        libc::munlock(self.ptr.cast(), self.page); libc::munmap(self.ptr.cast(), self.page);
    } }
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "camelCase", deny_unknown_fields)]
enum Request {
    Open { encrypted_key: String, iv: String, ciphertext: String },
    Digest { message: String },
    Destroy,
}
fn decode(value: &str, max: usize) -> Result<Vec<u8>> {
    if value.len() > max.div_ceil(3) * 4 { return Err(()); }
    let bytes = STANDARD.decode(value).map_err(|_| ())?;
    if bytes.len() > max || STANDARD.encode(&bytes) != value { return Err(()); }
    Ok(bytes)
}
fn open(key: &PKey<Private>, encrypted_key: &str, iv: &str, ciphertext: &str) -> Result<Secret> {
    let encrypted = decode(encrypted_key, 256)?;
    let iv = decode(iv, 16)?;
    let ciphertext = decode(ciphertext, 48)?;
    if encrypted.len() != 256 || iv.len() != 16 || ciphertext.len() != 48 { return Err(()); }
    let mut dec = Decrypter::new(key).map_err(|_| ())?;
    dec.set_rsa_padding(Padding::PKCS1_OAEP).map_err(|_| ())?;
    dec.set_rsa_oaep_md(MessageDigest::sha256()).map_err(|_| ())?;
    dec.set_rsa_mgf1_md(MessageDigest::sha256()).map_err(|_| ())?;
    let mut cek = Zeroizing::new(vec![0; 256]);
    let size = dec.decrypt(&encrypted, &mut cek).map_err(|_| ())?;
    if size != 32 { return Err(()); }
    let mut cipher = Crypter::new(Cipher::aes_256_cbc(), Mode::Decrypt, &cek[..32], Some(&iv)).map_err(|_| ())?;
    let mut plain = Zeroizing::new(vec![0; 64]);
    let n = cipher.update(&ciphertext, &mut plain).map_err(|_| ())?;
    let end = n + cipher.finalize(&mut plain[n..]).map_err(|_| ())?;
    if end != 32 { return Err(()); }
    Secret::new(&plain[..32])
}
fn emit(value: serde_json::Value) -> Result<()> {
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, &value).map_err(|_| ())?;
    stdout.write_all(b"\n").map_err(|_| ())?; stdout.flush().map_err(|_| ())
}
fn run() -> Result<()> {
    unsafe {
        let core = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 || libc::setrlimit(libc::RLIMIT_CORE, &core) != 0 { return Err(()); }
        // This helper has no verifier workload. Bound even a malformed caller.
        let address = libc::rlimit { rlim_cur: 128 * 1024 * 1024, rlim_max: 128 * 1024 * 1024 };
        if libc::setrlimit(libc::RLIMIT_AS, &address) != 0 { return Err(()); }
    }
    let mut recipient = Some(PKey::from_rsa(Rsa::generate(2048).map_err(|_| ())?).map_err(|_| ())?);
    let public = recipient.as_ref().ok_or(())?.public_key_to_der().map_err(|_| ())?;
    if public.len() != 294 { return Err(()); }
    emit(serde_json::json!({"publicKey": STANDARD.encode(public)}))?;
    let mut key: Option<Secret> = None;
    let mut input = io::stdin().lock();
    loop {
        let mut line = Zeroizing::new(Vec::new());
        // read_until alone is unbounded. Take at most MAX_LINE+1 bytes.
        let mut limited = (&mut input).take((MAX_LINE + 1) as u64);
        if limited.read_until(b'\n', &mut line).map_err(|_| ())? == 0 { return Ok(()); }
        if line.len() > MAX_LINE || line.last() != Some(&b'\n') { return Err(()); }
        match serde_json::from_slice::<Request>(&line).map_err(|_| ())? {
            Request::Open { encrypted_key, iv, ciphertext } => {
                if key.is_some() { return Err(()); }
                key = Some(open(recipient.as_ref().ok_or(())?, &encrypted_key, &iv, &ciphertext)?);
                recipient = None; // OpenSSL clears private RSA factors on free.
                emit(serde_json::json!({"ready": true}))?;
            }
            Request::Digest { message } => {
                let message = Zeroizing::new(message);
                let bytes = Zeroizing::new(decode(&message, 65536)?);
                let mac_key = PKey::hmac(key.as_ref().ok_or(())?.bytes()).map_err(|_| ())?;
                let mut signer = Signer::new(MessageDigest::sha256(), &mac_key).map_err(|_| ())?;
                signer.update(DOMAIN).map_err(|_| ())?; signer.update(&bytes).map_err(|_| ())?;
                emit(serde_json::json!({"mac": STANDARD.encode(signer.sign_to_vec().map_err(|_| ())?)}))?;
            }
            Request::Destroy => { drop(key); emit(serde_json::json!({"destroyed": true}))?; return Ok(()); }
        }
    }
}
fn main() {
    if run().is_err() { let _ = emit(serde_json::json!({"error": "KMS_NATIVE_REFUSED"})); std::process::exit(1); }
}
