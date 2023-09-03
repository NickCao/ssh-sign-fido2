use byteorder::BigEndian as E;
use byteorder::WriteBytesExt;
use clap::Parser;
use clap::ValueEnum;
use ctap_hid_fido2::public_key::PublicKeyType;
use ctap_hid_fido2::Cfg;
use ctap_hid_fido2::FidoKeyHidFactory;
use pem::Pem;
use sha2::Digest;
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

fn sign(message: &[u8], namespace: &str, rp_id: &str) -> String {
    const HASH_ALGO: &str = "sha512";
    const PIN: Option<&str> = None;

    let mut config = Cfg::init();
    config.keep_alive_msg = "".to_string();

    let device = FidoKeyHidFactory::create(&config).unwrap();

    let assertion = &device
        .get_assertions_rk(
            rp_id,
            &encode_signed_data(namespace, HASH_ALGO, &Sha512::digest(message)),
            PIN,
        )
        .unwrap()[0];

    let cred = &device
        .credential_management_enumerate_credentials(PIN, &assertion.rpid_hash)
        .unwrap()[0];

    let key_type = match cred.public_key.key_type {
        PublicKeyType::Ed25519 => "sk-ssh-ed25519@openssh.com",
        _ => unimplemented!(),
    };

    let signature = encode_signature_blob(
        &encode_publickey(key_type, &cred.public_key.der, rp_id),
        namespace,
        HASH_ALGO,
        &encode_signature(
            key_type,
            &assertion.signature,
            assertion.flags.as_u8(),
            assertion.sign_count,
        ),
    );

    let config = pem::EncodeConfig::new();
    let config = config.set_line_ending(pem::LineEnding::LF);
    let config = config.set_line_wrap(76);

    pem::encode_config(&Pem::new("SSH SIGNATURE", signature), config)
}

/// OpenSSH authentication key utility
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// signature-related options
    #[arg(short = 'Y', value_name = "OPERATION")]
    mode: Mode,

    /// signature namespace, used to prevent signature confusion across different domains of use
    #[arg(short = 'n')]
    namespace: String,

    /// path to private key file, actually interpreted as relying party id
    #[arg(short = 'f', value_name = "KEY_FILE")]
    key_file: String,

    file: String,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Mode {
    /// cryptographically sign a file or some data using an SSH key
    Sign,
}

fn main() {
    let args = Args::parse();

    match args.mode {
        Mode::Sign => {
            let data = std::fs::read(&args.file).unwrap();
            let sig = sign(&data, &args.namespace, &args.key_file);
            std::fs::write(args.file + ".sig", sig.as_bytes()).unwrap();
        }
    }
}
