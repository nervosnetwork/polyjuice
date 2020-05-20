use crate::storage::{Loader, Runner};
use crate::types::{EoaAddress, Program, TransactionReceipt};
use ckb_jsonrpc_types::JsonBytes;
use ckb_simple_account_layer::Config;
use ckb_types::H160;
use jsonrpc_core::{Error, ErrorCode, Result};
use jsonrpc_derive::rpc;
use std::error::Error as StdError;
use std::sync::Arc;

#[rpc(server)]
pub trait Rpc {
    // #[rpc(name = "static_call")]
    // fn static_call(&self) -> Result<JsonBytes>;

    // #[rpc(name = "call")]
    // fn call(&self) -> Result<TransactionReceipt>;

    #[rpc(name = "create")]
    fn create(&self, sender: H160, code: JsonBytes) -> Result<TransactionReceipt>;
}

pub struct RpcImpl {
    pub loader: Arc<Loader>,
    pub config: Config,
}

impl Rpc for RpcImpl {
    fn create(&self, sender: H160, code: JsonBytes) -> Result<TransactionReceipt> {
        let loader = Loader::clone(&self.loader);
        let config = self.config.clone();
        let program = Program::new_create(EoaAddress(sender), code.into_bytes());
        let mut runner = Runner::new(loader, config, program);
        runner.create().map_err(convert_err)
    }
}

fn convert_err(err: Box<dyn StdError>) -> Error {
    Error {
        code: ErrorCode::InvalidRequest,
        message: err.to_string(),
        data: None,
    }
}
