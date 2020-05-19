mod rpc_client;
mod storage;
mod types;

use ckb_types::{
    bytes::{BufMut, Bytes, BytesMut},
    H160, H256,
};
use clap::{App, Arg, SubCommand};
use std::fs;
use types::{CallKind, ContractAddress, EoaAddress, Program};

fn main() -> Result<(), String> {
    let matches = App::new("polyjuice")
        .subcommand(
            SubCommand::with_name("build-tx")
                .about("Build and serialize a eth transaction which will put into witness data")
                .arg(
                    Arg::with_name("call-kind")
                        .long("call-kind")
                        .takes_value(true)
                        .default_value("call")
                        .possible_values(&["create", "create2", "call", "callcode"])
                        .help("The kind of the call")
                )
                .arg(Arg::with_name("static").long("static").help("Is static call"))
                .arg(
                    Arg::with_name("signature")
                        .long("signature")
                        .takes_value(true)
                        .validator(|input| parse_hex_binary(input.as_str()).map(|_| ()))
                        .help("The signature (65 bytes)")
                )
                .arg(
                    Arg::with_name("depth")
                        .long("depth")
                        .takes_value(true)
                        .validator(|input| input.parse::<u32>().map(|_| ()).map_err(|err| err.to_string()))
                        .default_value("0")
                        .help("The call depth"),
                )
                .arg(
                    Arg::with_name("sender")
                        .long("sender")
                        .takes_value(true)
                        .validator(|input| parse_h160(input.as_str()).map(|_| ()))
                        .default_value("0x1111111111111111111111111111111111111111")
                        .help("The sender of the message")
                )
                .arg(
                    Arg::with_name("destination")
                        .long("destination")
                        .takes_value(true)
                        .validator(|input| parse_h160(input.as_str()).map(|_| ()))
                        .default_value("0x2222222222222222222222222222222222222222")
                        .help("The destination of the message")
                )
                .arg(
                    Arg::with_name("code")
                        .long("code")
                        .takes_value(true)
                        .required(true)
                        .validator(|input| parse_hex_binary(input.as_str()).map(|_| ()))
                        .help("The code to create/call the contract, hex file path or hex string")
                )
                .arg(
                    Arg::with_name("input")
                        .long("input")
                        .takes_value(true)
                        .validator(|input| parse_hex_binary(input.as_str()).map(|_| ()))
                        .help("The input data to create/call the contract, hex file path or hex string")
                )
        ).get_matches();

    match matches.subcommand() {
        ("build-tx", Some(m)) => {
            let signature = m
                .value_of("signature")
                .map(|input| {
                    let data = parse_hex_binary(input)?;
                    if data.len() != 65 {
                        return Err(format!("Invalid data length for signature: {}", data.len()));
                    }
                    let mut target = [0u8; 65];
                    target.copy_from_slice(data.as_ref());
                    Ok(target)
                })
                .transpose()?
                .unwrap_or([0u8; 65]);
            let kind: CallKind = m
                .value_of("call-kind")
                .map(|input| serde_json::from_str(format!("\"{}\"", input).as_str()).unwrap())
                .unwrap();
            let flags: u32 = if m.is_present("static") { 1 } else { 0 };
            let depth: u32 = m.value_of("depth").unwrap().parse::<u32>().unwrap();
            let sender = parse_h160(m.value_of("sender").unwrap())
                .map(EoaAddress)
                .unwrap();
            let destination = parse_h160(m.value_of("destination").unwrap())
                .map(ContractAddress)
                .unwrap();
            let code = parse_hex_binary(m.value_of("code").unwrap())
                .map(Bytes::from)
                .unwrap();
            let input = parse_hex_binary(m.value_of("input").unwrap_or(""))
                .map(Bytes::from)
                .unwrap();
            let program = Program {
                kind,
                flags,
                depth,
                sender,
                destination,
                code,
                input,
            };

            let program_data = program.serialize();
            let mut out_data = BytesMut::with_capacity(signature.len() + program_data.len());
            out_data.put(&signature[..]);
            out_data.put(program_data.as_ref());
            println!(
                "[length]: {}",
                hex::encode(&(out_data.len() as u32).to_le_bytes()[..])
            );
            println!("[binary]: {}", hex::encode(&out_data));
        }
        _ => println!("{}", matches.usage()),
    }
    Ok(())
}

fn parse_h160(input: &str) -> Result<H160, String> {
    serde_json::from_str(format!("\"{}\"", input).as_str()).map_err(|err| err.to_string())
}

fn parse_hex_binary(input: &str) -> Result<Vec<u8>, String> {
    hex::decode(input)
        .map_err(|err| err.to_string())
        .or_else(|err| {
            let content = fs::read_to_string(input).map_err(|err| err.to_string())?;
            hex::decode(&content).map_err(|err| err.to_string())
        })
}
