use crate::storage::{Loader, Runner};
use crate::types::{
    ContractAddress, ContractCode, EoaAddress, Program, RunConfig, TransactionReceipt,
};
use ckb_jsonrpc_types::JsonBytes;
use ckb_types::{H160, H256};
use jsonrpc_core::{Error, ErrorCode, Result};
use jsonrpc_derive::rpc;
use serde::Serialize;
use std::error::Error as StdError;
use std::sync::Arc;

#[rpc(server)]
pub trait Rpc {
    // #[rpc(name = "static_call")]
    // fn static_call(&self) -> Result<JsonBytes>;

    // #[rpc(name = "call")]
    // fn call(&self) -> Result<TransactionReceipt>;

    #[rpc(name = "get_code")]
    fn get_code(&self, address: H160) -> Result<ContractCodeJson>;

    #[rpc(name = "create")]
    fn create(&self, sender: H160, code: JsonBytes) -> Result<TransactionReceipt>;
}

pub struct RpcImpl {
    pub loader: Arc<Loader>,
    pub run_config: RunConfig,
}

impl Rpc for RpcImpl {
    fn get_code(&self, address: H160) -> Result<ContractCodeJson> {
        let address = ContractAddress(address);
        let code = self
            .loader
            .load_contract_code(address)
            .map_err(convert_err)?;
        Ok(code.into())
    }

    fn create(&self, sender: H160, code: JsonBytes) -> Result<TransactionReceipt> {
        let loader = Loader::clone(&self.loader);
        let run_config = self.run_config.clone();
        let program = Program::new_create(EoaAddress(sender), code.into_bytes());
        let mut runner = Runner::new(loader, run_config, program);
        runner.create().map_err(convert_err_box)
    }
}

fn convert_err(err: String) -> Error {
    Error {
        code: ErrorCode::InvalidRequest,
        message: err,
        data: None,
    }
}

fn convert_err_box(err: Box<dyn StdError>) -> Error {
    Error {
        code: ErrorCode::InvalidRequest,
        message: err.to_string(),
        data: None,
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct ContractCodeJson {
    pub code: JsonBytes,
    /// The hash of the transaction where the contract created
    pub tx_hash: H256,
    /// The output index of the transaction where the contract created
    pub output_index: u32,
}
impl From<ContractCode> for ContractCodeJson {
    fn from(cc: ContractCode) -> ContractCodeJson {
        ContractCodeJson {
            code: JsonBytes::from_bytes(cc.code),
            tx_hash: cc.tx_hash,
            output_index: cc.output_index,
        }
    }
}
