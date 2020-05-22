mod client;
mod server;
mod storage;
mod types;

use jsonrpc_core::IoHandler;
use jsonrpc_http_server::ServerBuilder;
use jsonrpc_server_utils::cors::AccessControlAllowOrigin;
use jsonrpc_server_utils::hosts::DomainsValidation;

use ckb_hash::new_blake2b;
use ckb_jsonrpc_types as json_types;
use ckb_types::{
    bytes::{BufMut, Bytes, BytesMut},
    core, packed,
    prelude::*,
    H160, H256,
};
use clap::{App, Arg, SubCommand};
use log::info;
use rocksdb::DB;
use serde::{Deserialize, Serialize};
use server::{Rpc, RpcImpl};
use std::convert::TryFrom;
use std::fs;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use storage::{Indexer, Loader};
use types::{
    CallKind, ContractAddress, EoaAddress, Program, RunConfig, TransactionReceipt, WitnessData,
    SECP256K1,
};

fn main() -> Result<(), String> {
    env_logger::init();

    let matches = App::new("polyjuice")
        .subcommand(
            SubCommand::with_name("run")
                .about("Run the polyjuice server")
                .arg(
                    Arg::with_name("generator")
                        .long("generator")
                        .takes_value(true)
                        .required(true)
                        .validator(|input| fs::File::open(input).map(|_| ()).map_err(|err| err.to_string()))
                        .help("The generator riscv binary")
                )
                .arg(
                    Arg::with_name("config")
                        .long("config")
                        .takes_value(true)
                        .required(true)
                        .validator(|input| fs::File::open(input).map(|_| ()).map_err(|err| err.to_string()))
                        .help("The config (json)")
                )
                .arg(
                    Arg::with_name("url")
                        .long("url")
                        .takes_value(true)
                        .required(true)
                        .default_value("http://127.0.0.1:8114")
                        .help("The ckb rpc url")
                )
        )
        .subcommand(
            SubCommand::with_name("sign-tx")
                .arg(
                    Arg::with_name("tx-receipt")
                        .long("tx-receipt")
                        .short("t")
                        .takes_value(true)
                        .required(true)
                        .validator(|input| fs::File::open(input).map(|_| ()).map_err(|err| err.to_string()))
                        .help("The transaction receipt file (json)")
                )
                .arg(
                    Arg::with_name("privkey")
                        .long("privkey")
                        .short("k")
                        .takes_value(true)
                        .required(true)
                        .validator(|input| fs::File::open(input).map(|_| ()).map_err(|err| err.to_string()))
                        .help("The private key file (hex)")
                )
                .arg(
                    Arg::with_name("output")
                        .long("output")
                        .short("o")
                        .takes_value(true)
                        .help("The output file path")
                )
        )
        .subcommand(
            SubCommand::with_name("build-tx")
                .about("Build and serialize a eth transaction which will put into witness data")
                .arg(
                    Arg::with_name("call-kind")
                        .long("call-kind")
                        .takes_value(true)
                        .default_value("call")
                        .possible_values(&["create", "call"])
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
        ("run", Some(m)) => {
            let generator = fs::read(m.value_of("generator").unwrap())
                .map(Bytes::from)
                .map_err(|err| err.to_string())?;
            let config_json: RunConfigJson = fs::read_to_string(m.value_of("config").unwrap())
                .map_err(|err| err.to_string())
                .and_then(|json_string| {
                    serde_json::from_str(json_string.as_str()).map_err(|err| err.to_string())
                })?;
            let run_config = RunConfig {
                generator,
                type_dep: config_json.type_dep.into(),
                type_script: config_json.type_script.into(),
                lock_dep: config_json.lock_dep.into(),
                lock_script: config_json.lock_script.into(),
            };
            let ckb_uri = m.value_of("url").unwrap();

            let db = Arc::new(DB::open_default("./data").expect("rocksdb"));
            let loader = Arc::new(Loader::new(Arc::clone(&db), ckb_uri).expect("loader failure"));
            let mut indexer = Indexer::new(Arc::clone(&db), ckb_uri, run_config.clone());
            let _ = thread::spawn(move || indexer.index().expect("indexer faliure"));

            let mut io_handler = IoHandler::new();
            io_handler.extend_with(
                RpcImpl {
                    loader: Arc::clone(&loader),
                    run_config,
                }
                .to_delegate(),
            );

            let rpc_url = "127.0.0.1:8214";
            let rpc_server = ServerBuilder::new(io_handler)
                .cors(DomainsValidation::AllowOnly(vec![
                    AccessControlAllowOrigin::Null,
                    AccessControlAllowOrigin::Any,
                ]))
                .threads(4)
                .max_request_body_size(10_485_760)
                .start_http(&rpc_url.parse().expect("parse listen address"))
                .expect("jsonrpc initialize");
            log::info!("RPC server listen on: {}", rpc_url);

            // Wait for exit
            let exit = Arc::new((Mutex::new(()), Condvar::new()));
            let e = Arc::clone(&exit);
            ctrlc::set_handler(move || {
                e.1.notify_all();
            })
            .expect("error setting Ctrl-C handler");
            let _guard = exit
                .1
                .wait(exit.0.lock().expect("locking"))
                .expect("waiting");
            rpc_server.close();
            log::info!("exiting...");
        }
        ("sign-tx", Some(m)) => {
            let mut tx_receipt: TransactionReceipt =
                fs::read_to_string(m.value_of("tx-receipt").unwrap())
                    .map_err(|err| err.to_string())
                    .and_then(|json_string| {
                        serde_json::from_str(json_string.as_str()).map_err(|err| err.to_string())
                    })?;
            let privkey = fs::read_to_string(m.value_of("privkey").unwrap())
                .map_err(|err| err.to_string())
                .and_then(|privkey| {
                    hex::decode(&privkey.trim().as_bytes()[0..64]).map_err(|err| err.to_string())
                })
                .and_then(|data| {
                    secp256k1::SecretKey::from_slice(data.as_slice()).map_err(|err| err.to_string())
                })?;
            // TODO: may not just the first witness
            let raw_witness =
                packed::WitnessArgs::from_slice(tx_receipt.tx.witnesses[0].as_bytes())
                    .map_err(|err| err.to_string())
                    .and_then(|witness_args| {
                        witness_args
                            .output_type()
                            .to_opt()
                            .ok_or_else(|| String::from("can not find output_type in witness"))
                    })
                    .map(|witness_data| witness_data.raw_data())?;
            let mut witness_data = WitnessData::try_from(raw_witness.as_ref())?;

            let tx = packed::Transaction::from(tx_receipt.tx.clone());
            let tx_hash: H256 = tx.calc_tx_hash().unpack();
            let message = witness_data.secp_message(&tx_hash)?;
            let signature = SECP256K1.sign_recoverable(&message, &privkey);
            let (recov_id, data) = signature.serialize_compact();
            let mut signature_bytes = [0u8; 65];
            signature_bytes[0..64].copy_from_slice(&data[0..64]);
            signature_bytes[64] = recov_id.to_i32() as u8;

            witness_data.signature = Bytes::from(signature_bytes.to_vec());
            let raw_witness = witness_data.serialize();
            let data = packed::BytesOpt::new_builder()
                .set(Some(raw_witness.pack()))
                .build();
            let witness = packed::WitnessArgs::from_slice(tx_receipt.tx.witnesses[0].as_bytes())
                .unwrap()
                .as_builder()
                .output_type(data)
                .build();
            tx_receipt.tx.witnesses[0] = json_types::JsonBytes::from_bytes(witness.as_bytes());
            let json_string = serde_json::to_string_pretty(&tx_receipt).unwrap();
            if let Some(output) = m.value_of("output") {
                fs::write(output, json_string.as_bytes()).map_err(|err| err.to_string())?;
            } else {
                println!("{}", json_string);
            }
        }
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
            let program_data = WitnessData::new(program).program_data();
            println!(
                "[length]: {}",
                hex::encode(&(program_data.len() as u32).to_le_bytes()[..])
            );
            println!("[binary]: {}", hex::encode(program_data.as_ref()));
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
        .or_else(|_err| {
            let content = fs::read_to_string(input).map_err(|err| err.to_string())?;
            hex::decode(&content).map_err(|err| err.to_string())
        })
}

// Can deploy those scripts by:
//     ckb-cli wallet transfer --data-path xxx
#[derive(Debug, Serialize, Deserialize)]
pub struct RunConfigJson {
    // Type script (Validator)
    pub type_dep: json_types::CellDep,
    pub type_script: json_types::Script,
    // Lock script
    pub lock_dep: json_types::CellDep,
    pub lock_script: json_types::Script,
}

pub fn build_signature<S: FnMut(&H256) -> Result<[u8; 65], String>>(
    tx: &core::TransactionView,
    input_group_idxs: &[usize],
    witnesses: &[packed::Bytes],
    mut signer: S,
) -> Result<Bytes, String> {
    let init_witness_idx = input_group_idxs[0];
    let init_witness = if witnesses[init_witness_idx].raw_data().is_empty() {
        packed::WitnessArgs::default()
    } else {
        packed::WitnessArgs::from_slice(witnesses[init_witness_idx].raw_data().as_ref())
            .map_err(|err| err.to_string())?
    };

    let init_witness = init_witness
        .as_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build();

    let mut blake2b = new_blake2b();
    blake2b.update(tx.hash().as_slice());
    blake2b.update(&(init_witness.as_bytes().len() as u64).to_le_bytes());
    blake2b.update(&init_witness.as_bytes());
    for idx in input_group_idxs.iter().skip(1).cloned() {
        let other_witness: &packed::Bytes = &witnesses[idx];
        blake2b.update(&(other_witness.len() as u64).to_le_bytes());
        blake2b.update(&other_witness.raw_data());
    }
    let mut message = [0u8; 32];
    blake2b.finalize(&mut message);
    let message = H256::from(message);
    signer(&message).map(|data| Bytes::from(data.to_vec()))
}
