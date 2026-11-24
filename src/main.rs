use std::env;
use std::process;
use stverify::{cmd_keygen, cmd_sign, cmd_sign_dir, cmd_verify, cmd_verify_dir, print_usage};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        process::exit(1);
    }

    match args[1].as_str() {
        "keygen" => {
            if args.len() != 4 {
                eprintln!("Usage: stverify keygen <privkey.hex> <pubkey.hex>");
                process::exit(1);
            }
            cmd_keygen(&args[2], &args[3]);
        }
        "sign" => {
            if args.len() != 5 {
                eprintln!("Usage: stverify sign <model.safetensors> <privkey.hex> <out.sig>");
                process::exit(1);
            }
            cmd_sign(&args[2], &args[3], &args[4]);
        }
        "verify" => {
            if args.len() != 5 {
                eprintln!("Usage: stverify verify <model.safetensors> <pubkey.hex> <model.sig>");
                process::exit(1);
            }
            cmd_verify(&args[2], &args[3], &args[4]);
        }
        "sign-dir" => {
            if args.len() != 4 {
                eprintln!("Usage: stverify sign-dir <model_dir> <privkey.hex>");
                process::exit(1);
            }
            cmd_sign_dir(&args[2], &args[3]);
        }
        "verify-dir" => {
            if args.len() != 4 {
                eprintln!("Usage: stverify verify-dir <model_dir> <pubkey.hex>");
                process::exit(1);
            }
            cmd_verify_dir(&args[2], &args[3]);
        }
        _ => {
            print_usage();
            process::exit(1);
        }
    }
}
