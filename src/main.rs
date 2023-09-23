use authenticator::authenticatorservice::AuthenticatorService;
use authenticator::authenticatorservice::SignArgs;
use authenticator::ctap2::server::AuthenticationExtensionsClientInputs;
use authenticator::ctap2::server::UserVerificationRequirement;
use authenticator::statecallback::StateCallback;
use authenticator::Pin;
use authenticator::StatusPinUv;
use authenticator::StatusUpdate;
use byteorder::BigEndian as E;
use byteorder::WriteBytesExt;
use clap::Parser;
use clap::ValueEnum;
use ctap_hid_fido2::public_key::PublicKeyType;
use ctap_hid_fido2::Cfg;
use ctap_hid_fido2::FidoKeyHidFactory;
use pem::Pem;
use secrecy::ExposeSecret;
use sha2::Digest;
use sha2::Sha256;
use sha2::Sha512;
use std::io::Write;
use std::sync::mpsc::channel;
use std::thread;

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

    let pin = if let Some(mut input) = pinentry::PassphraseInput::with_default_binary() {
        Some(
            input
                .with_prompt("Enter FIDO2 Pin:")
                .interact()
                .unwrap()
                .expose_secret()
                .to_owned(),
        )
    } else {
        None
    };

    let mut manager =
        AuthenticatorService::new().expect("The auth service should initialize safely");
    manager.add_u2f_usb_hid_platform_transports();

    let (status_tx, status_rx) = channel::<StatusUpdate>();
    thread::spawn(move || loop {
        match status_rx.recv() {
            Ok(StatusUpdate::InteractiveManagement(..)) => {
                panic!("STATUS: This can't happen when doing non-interactive usage");
            }
            Ok(StatusUpdate::SelectDeviceNotice) => {
                println!("STATUS: Please select a device by touching one of them.");
            }
            Ok(StatusUpdate::PresenceRequired) => {
                println!("STATUS: waiting for user presence");
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::PinRequired(sender))) => {
                sender
                    .send(Pin::new(&pin.clone().unwrap()))
                    .expect("Failed to send PIN");
                continue;
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::InvalidPin(sender, attempts))) => {
                sender
                    .send(Pin::new(&pin.clone().unwrap()))
                    .expect("Failed to send PIN");
                continue;
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::PinAuthBlocked)) => {
                panic!("Too many failed attempts in one row. Your device has been temporarily blocked. Please unplug it and plug in again.")
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::PinBlocked)) => {
                panic!("Too many failed attempts. Your device has been blocked. Reset it.")
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::InvalidUv(attempts))) => {
                println!(
                    "Wrong UV! {}",
                    attempts.map_or("Try again.".to_string(), |a| format!(
                        "You have {a} attempts left."
                    ))
                );
                continue;
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::UvBlocked)) => {
                println!("Too many failed UV-attempts.");
                continue;
            }
            Ok(StatusUpdate::PinUvError(e)) => {
                panic!("Unexpected error: {:?}", e)
            }
            Ok(StatusUpdate::SelectResultNotice(index_sender, users)) => {
                println!("Multiple signatures returned. Select one or cancel.");
                index_sender.send(None).expect("Failed to send choice");
            }
            Err(RecvError) => {
                println!("STATUS: end");
                return;
            }
        }
    });

    let mut challenge = Sha256::new();
    challenge.update(message);
    let chall_bytes = challenge.finalize().into();
    let ctap_args = SignArgs {
        client_data_hash: chall_bytes,
        origin: rp_id.to_string(),
        relying_party_id: rp_id.to_string(),
        allow_list: vec![],
        user_verification_req: UserVerificationRequirement::Required,
        user_presence_req: true,
        extensions: AuthenticationExtensionsClientInputs {
            ..Default::default()
        },
        pin: None,
        use_ctap1_fallback: false,
    };

    loop {
        let (sign_tx, sign_rx) = channel();

        let callback = StateCallback::new(Box::new(move |rv| {
            sign_tx.send(rv).unwrap();
        }));

        if let Err(e) = manager.sign(0, ctap_args, status_tx, callback) {
            panic!("Couldn't sign: {:?}", e);
        }

        let sign_result = sign_rx
            .recv()
            .expect("Problem receiving, unable to continue");

        match sign_result {
            Ok(assertion_object) => {
                dbg!(assertion_object);
                /*

                let key_type = match cred.public_key.key_type {
                    PublicKeyType::Ed25519 => "sk-ssh-ed25519@openssh.com",
                    _ => unimplemented!(),
                };
                let key_type = "sk-ssh-ed25519@openssh.com";
                let pub_key = vec![];

                let signature = encode_signature_blob(
                    &encode_publickey(key_type, &pub_key, rp_id),
                    namespace,
                    HASH_ALGO,
                    &encode_signature(
                        key_type,
                        &assertion_object.assertion.signature,
                        assertion_object.assertion.auth_data.flags.bits(),
                        assertion_object.assertion.auth_data.counter,
                    ),
                );

                let config = pem::EncodeConfig::new();
                let config = config.set_line_ending(pem::LineEnding::LF);
                let config = config.set_line_wrap(76);

                return pem::encode_config(&Pem::new("SSH SIGNATURE", signature), config);
                */
                return "".to_string();
            }
            Err(e) => panic!("Signing failed: {:?}", e),
        }
    }
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
