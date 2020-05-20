mod client;
mod server;
mod storage;
mod types;

use jsonrpc_core::IoHandler;
use jsonrpc_http_server::ServerBuilder;
use jsonrpc_server_utils::cors::AccessControlAllowOrigin;
use jsonrpc_server_utils::hosts::DomainsValidation;

use ckb_simple_account_layer::Config;
use ckb_types::{
    bytes::{BufMut, Bytes, BytesMut},
    H160,
};
use clap::{App, Arg, SubCommand};
use log::info;
use rocksdb::DB;
use server::{Rpc, RpcImpl};
use std::fs;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use storage::{Indexer, Loader};
use types::{
    CallKind, ContractAddress, EoaAddress, Program, ALWAYS_SUCCESS_OUT_POINT, ALWAYS_SUCCESS_SCRIPT,
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
            let mut config = Config::default();
            config.generator = generator;
            // FIXME: use real script later
            config.validator_outpoint = ALWAYS_SUCCESS_OUT_POINT.clone();
            // FIXME: use real script later
            config.type_script = ALWAYS_SUCCESS_SCRIPT.clone();

            let db = Arc::new(DB::open_default("./data").expect("rocksdb"));
            let ckb_uri = "http://127.0.0.1:8114";
            let loader = Arc::new(Loader::new(Arc::clone(&db), ckb_uri).expect("loader failure"));
            let mut indexer = Indexer::new(Arc::clone(&db), ckb_uri, config.clone());
            let _ = thread::spawn(move || indexer.index().expect("indexer faliure"));

            let mut io_handler = IoHandler::new();
            io_handler.extend_with(
                RpcImpl {
                    loader: Arc::clone(&loader),
                    config,
                }
                .to_delegate(),
            );

            let rpc_server = ServerBuilder::new(io_handler)
                .cors(DomainsValidation::AllowOnly(vec![
                    AccessControlAllowOrigin::Null,
                    AccessControlAllowOrigin::Any,
                ]))
                .threads(4)
                .max_request_body_size(10_485_760)
                .start_http(&"127.0.0.1:8214".parse().expect("parse listen address"))
                .expect("jsonrpc initialize");

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
            info!("exiting...");
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
        .or_else(|_err| {
            let content = fs::read_to_string(input).map_err(|err| err.to_string())?;
            hex::decode(&content).map_err(|err| err.to_string())
        })
}
