use std::process::exit;

use clap::Parser;
use hmac::{Hmac, Mac};
use rand::{Rng, rngs::StdRng};
use sha1::Sha1;

#[derive(Parser)]
struct ExampleDeriveArgs {
    secret: Option<String>,
    code: Option<String>,
}

fn main() {
    let args = ExampleDeriveArgs::parse();

    match (args.secret, args.code) {
        (Some(secret), None) => match gen_code(secret) {
            Ok(code) => {
                println!("{}", code);
            }
            Err(e) => {
                println!("error generating code: {}", e);
                exit(1)
            }
        },
        (Some(secret), Some(input_code)) => match gen_code(secret) {
            Ok(code) => {
                if input_code == code {
                    println!("TOTP code is correct");
                } else {
                    println!("TOTP code is incorrect (expected {})", code);
                    exit(1)
                }
            }
            Err(e) => {
                println!("error generating code: {}", e);
                exit(1)
            }
        },
        (None, _) => {
            println!("{}", generate_secret());
        }
    }
}

fn generate_secret() -> String {
    let mut buff = [0u8; 20];
    let mut rng: StdRng = rand::make_rng();
    rng.fill_bytes(&mut buff);
    base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &buff).to_string()
}

type HmacSha1 = Hmac<Sha1>;

fn gen_code(secret: String) -> Result<String, String> {
    let big_counter = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 30;

    let decoded_secret = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &secret)
        .ok_or("Failed to decode secret, is it base32?")?;

    let mut mac = HmacSha1::new_from_slice(&decoded_secret).expect("HMAC can take key of any size");
    mac.update(&big_counter.to_be_bytes());

    let result = mac.finalize().into_bytes();
    let mut output = [0u8; 20].to_vec();
    output.copy_from_slice(&result);

    let offset: usize = (output[19] & 0x0f) as usize;
    let long_code = u32::from_be_bytes(
        output[offset..offset + 4]
            .try_into()
            .map_err(|_| "hamc shorter than expected")?,
    ) & 0x7fff_ffff;
    let truncated_code = long_code % 1000000;

    Ok(format!("{:}", truncated_code))
}
