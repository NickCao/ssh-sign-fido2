use byteorder::BigEndian as E;
use byteorder::WriteBytesExt;
use ed25519_dalek::{Signature, Signer, SigningKey};
use pem::Pem;
use rand::rngs::OsRng;
use sha2::Digest;
use sha2::Sha256;
use sha2::Sha512;
use std::io::Write;

const MAGIC_PREAMBLE: &[u8] = b"SSHSIG";
const SIG_VERSION: u32 = 0x01;

pub trait WriteString: std::io::Write {
    fn write_string(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.write_u32::<E>(buf.len().try_into().unwrap())?;
        self.write_all(buf)?;
        Ok(())
    }
}

impl<T: std::io::Write> WriteString for T {}

fn encode_signed_data(namespace: &str, hash_algorithm: &str, hash: &[u8]) -> Vec<u8> {
    // Reference: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig
    // 3. Signed Data, of which the signature goes into the blob above
    let mut buf = vec![];
    // byte[6]   MAGIC_PREAMBLE
    buf.write_all(MAGIC_PREAMBLE).unwrap();
    // string    namespace
    buf.write_string(namespace.as_bytes()).unwrap();
    // string    reserved
    buf.write_string(b"").unwrap();
    // string    hash_algorithm
    buf.write_string(hash_algorithm.as_bytes()).unwrap();
    // string    H(message)
    buf.write_string(hash).unwrap();
    buf
}

fn encode_signature_blob(
    publickey: &[u8],
    namespace: &str,
    hash_algorithm: &str,
    signature: &[u8],
) -> Vec<u8> {
    // Reference: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig
    // 2. Blob format
    let mut buf = vec![];
    // byte[6]   MAGIC_PREAMBLE
    buf.write_all(MAGIC_PREAMBLE).unwrap();
    // uint32    SIG_VERSION
    buf.write_u32::<E>(SIG_VERSION).unwrap();
    // string    publickey
    buf.write_string(&publickey).unwrap();
    // string    namespace
    buf.write_string(namespace.as_bytes()).unwrap();
    // string    reserved
    buf.write_string(b"").unwrap();
    // string    hash_algorithm
    buf.write_string(hash_algorithm.as_bytes()).unwrap();
    // string    signature
    buf.write_string(&signature).unwrap();
    buf
}

fn encode_wrapped_signed_data(
    application: &str,
    flags: u8,
    counter: u32,
    message: &[u8],
) -> Vec<u8> {
    // Reference: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.u2f
    // In addition to the message to be signed, the U2F signature operation
    // requires the key handle and a few additional parameters. The signature
    // is signed over a blob that consists of:
    let mut buf = vec![];
    // byte[32]	SHA256(application)
    buf.write_all(&Sha256::digest(application.as_bytes()))
        .unwrap();
    // byte		flags (including "user present", extensions present)
    buf.write_u8(flags).unwrap();
    // uint32	counter
    buf.write_u32::<E>(counter).unwrap();
    // byte[]	extensions
    // byte[32]	SHA256(message)
    buf.write_all(&Sha256::digest(message)).unwrap();
    buf
}

fn encode_publickey(r#type: &str, publickey: &[u8], application: &str) -> Vec<u8> {
    // Reference: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.u2f
    let mut buf = vec![];
    match r#type {
        // The format of a sk-ssh-ed25519@openssh.com public key is:
        "sk-ssh-ed25519@openssh.com" => {
            // string		"sk-ssh-ed25519@openssh.com"
            buf.write_string(r#type.as_bytes()).unwrap();
            // string		public key
            buf.write_string(publickey).unwrap();
            // string		application (user-specified, but typically "ssh:")
            buf.write_string(application.as_bytes()).unwrap();
        }
        _ => unimplemented!(),
    }
    buf
}

fn encode_signature(r#type: &str, signature: &[u8], flags: u8, counter: u32) -> Vec<u8> {
    // Reference: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.u2f
    let mut buf = vec![];
    match r#type {
        "sk-ssh-ed25519@openssh.com" => {
            // string		"sk-ssh-ed25519@openssh.com"
            buf.write_string(r#type.as_bytes()).unwrap();
            // string		signature
            buf.write_string(signature).unwrap();
            // byte         flags
            buf.write_u8(flags).unwrap();
            // uint32		counter
            buf.write_u32::<E>(counter).unwrap();
        }
        _ => unimplemented!(),
    }
    buf
}

fn sign(signer: ed25519_dalek::SigningKey, message: &[u8], flags: u8, counter: u32) {
    const TYPE: &str = "sk-ssh-ed25519@openssh.com";
    const HASH_ALGO: &str = "sha512";
    const NAMESPACE: &str = "git";
    const APPLICATION: &str = "ssh:something";

    let signature: Signature = signer.sign(&encode_wrapped_signed_data(
        APPLICATION,
        flags,
        counter,
        &encode_signed_data(NAMESPACE, HASH_ALGO, &Sha512::digest(message)),
    ));

    // println!("sk-ssh-ed25519@openssh.com {}", base64::encode(&publickey));

    let signature = encode_signature_blob(
        &encode_publickey(TYPE, signer.verifying_key().as_bytes(), APPLICATION),
        NAMESPACE,
        HASH_ALGO,
        &encode_signature(TYPE, &signature.to_vec(), flags, counter),
    );

    let config = pem::EncodeConfig::new();
    let config = config.set_line_ending(pem::LineEnding::LF);
    let config = config.set_line_wrap(76);

    print!(
        "{}",
        pem::encode_config(&Pem::new("SSH SIGNATURE", signature), config)
    );
}

fn main() {
    let mut csprng = OsRng;
    let signing_key: SigningKey = SigningKey::generate(&mut csprng);
    sign(signing_key, b"hello", 4, 1000);
}
