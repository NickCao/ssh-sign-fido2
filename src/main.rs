use authenticator::{
    authenticatorservice::{AuthenticatorService, SignArgs},
    crypto::{COSEKeyType, COSEOKPKey, Curve},
    ctap2::{commands::credential_management::CredentialList, server::UserVerificationRequirement},
    statecallback::StateCallback,
    CredManagementCmd, CredentialManagementResult, InteractiveRequest, InteractiveUpdate, Pin,
    StatusPinUv, StatusUpdate,
};
use byteorder::{BigEndian as E, WriteBytesExt};
use clap::{Parser, ValueEnum};
use pem::Pem;
use secrecy::ExposeSecret;
use sha2::{Digest, Sha256, Sha512};
use std::{io::Write, sync::mpsc::channel};

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
    buf.write_string(publickey).unwrap();
    // string    namespace
    buf.write_string(namespace.as_bytes()).unwrap();
    // string    reserved
    buf.write_string(b"").unwrap();
    // string    hash_algorithm
    buf.write_string(hash_algorithm.as_bytes()).unwrap();
    // string    signature
    buf.write_string(signature).unwrap();
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

    let mut manager = AuthenticatorService::new().unwrap();

    manager.add_detected_transports();

    let (pub_tx, pub_rx) = channel::<CredentialList>();

    let (tx, rx) = channel::<StatusUpdate>();

    std::thread::spawn(move || -> anyhow::Result<()> {
        for update in rx.iter() {
            match update {
                StatusUpdate::InteractiveManagement(management) => match management {
                    InteractiveUpdate::StartManagement((sender, _)) => {
                        let request = InteractiveRequest::CredentialManagement(
                            CredManagementCmd::GetCredentials,
                            None,
                        );
                        sender.send(request)?;
                        sender.send(InteractiveRequest::Quit)?;
                    }
                    InteractiveUpdate::CredentialManagementUpdate((
                        CredentialManagementResult::CredentialList(creds),
                        _,
                    )) => {
                        pub_tx.send(creds)?;
                    }
                    _ => unreachable!(),
                },
                StatusUpdate::SelectDeviceNotice => println!("select device by touching"),
                StatusUpdate::PresenceRequired => eprintln!("waiting for user presence"),
                StatusUpdate::PinUvError(StatusPinUv::PinRequired(sender)) => {
                    let pin = pinentry::PassphraseInput::with_default_binary().map(|mut input| {
                        input
                            .with_prompt("Enter FIDO2 Pin:")
                            .interact()
                            .unwrap()
                            .expose_secret()
                            .to_owned()
                    });
                    sender.send(Pin::new(&pin.unwrap())).unwrap();
                }
                StatusUpdate::PinUvError(StatusPinUv::InvalidPin(sender, _attempts)) => {
                    let pin = pinentry::PassphraseInput::with_default_binary().map(|mut input| {
                        input
                            .with_prompt("Enter FIDO2 Pin:")
                            .interact()
                            .unwrap()
                            .expose_secret()
                            .to_owned()
                    });
                    sender.send(Pin::new(&pin.unwrap())).unwrap();
                }
                StatusUpdate::PinUvError(err) => {
                    eprintln!("user verification error: {:?}", err)
                }
                StatusUpdate::SelectResultNotice(index_sender, _users) => {
                    println!("Multiple signatures returned. Select one or cancel.");
                    index_sender.send(None).expect("Failed to send choice");
                }
            }
        }
        Ok(())
    });

    let ctap_args = SignArgs {
        client_data_hash: Sha256::digest(encode_signed_data(
            namespace,
            HASH_ALGO,
            &Sha512::digest(message),
        ))
        .into(),
        origin: rp_id.to_string(),
        relying_party_id: rp_id.to_string(),
        allow_list: vec![],
        user_verification_req: UserVerificationRequirement::Required,
        user_presence_req: true,
        extensions: Default::default(),
        pin: None,
        use_ctap1_fallback: false,
    };

    let (sign_tx, sign_rx) = channel();

    let callback = StateCallback::new(Box::new(move |rv| {
        sign_tx.send(rv).unwrap();
    }));

    if let Err(e) = manager.sign(0, ctap_args, tx.clone(), callback) {
        panic!("Couldn't sign: {:?}", e);
    }

    let assertion = sign_rx.recv().unwrap().unwrap().assertion;

    let keyid = assertion.credentials.unwrap().id;

    let (mgmt_tx, mgmt_rx) = channel();

    let callback_2 = StateCallback::new(Box::new(move |rv| {
        mgmt_tx.send(rv).unwrap();
    }));

    if let Err(e) = manager.manage(0, tx, callback_2) {
        panic!("Couldn't manage: {:?}", e);
    }

    for result in mgmt_rx.iter() {
        result.unwrap();
    }

    let pubkey = pub_rx
        .recv()
        .unwrap()
        .credential_list
        .into_iter()
        .flat_map(|rp| rp.credentials)
        .find(|cred| cred.credential_id.id == keyid)
        .unwrap()
        .public_key;

    let (key_type, key) = match pubkey.key {
        COSEKeyType::OKP(COSEOKPKey {
            curve: Curve::Ed25519,
            x,
        }) => ("sk-ssh-ed25519@openssh.com", x),
        _ => unimplemented!(),
    };

    let signature = encode_signature_blob(
        &encode_publickey(key_type, &key, rp_id),
        namespace,
        HASH_ALGO,
        &encode_signature(
            key_type,
            &assertion.signature,
            assertion.auth_data.flags.bits(),
            assertion.auth_data.counter,
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
