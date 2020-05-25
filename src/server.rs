use crate::storage::{Loader, Runner};
use crate::types::{
    ContractAddress, ContractChange, ContractCode, EoaAddress, Program, RunConfig,
    TransactionReceipt,
};
use ckb_jsonrpc_types::JsonBytes;
use ckb_types::H256;
use jsonrpc_core::{Error, ErrorCode, Result};
use jsonrpc_derive::rpc;
use serde::Serialize;
use std::error::Error as StdError;
use std::sync::Arc;

#[rpc(server)]
pub trait Rpc {
    #[rpc(name = "get_code")]
    fn get_code(&self, contract_address: ContractAddress) -> Result<ContractCodeJson>;

    #[rpc(name = "get_change")]
    fn get_change(
        &self,
        contract_address: ContractAddress,
        block_number: Option<u64>,
    ) -> Result<ContractChangeJson>;

    #[rpc(name = "static_call")]
    fn static_call(
        &self,
        sender: EoaAddress,
        contract_address: ContractAddress,
        input: JsonBytes,
    ) -> Result<JsonBytes>;

    #[rpc(name = "call")]
    fn call(
        &self,
        sender: EoaAddress,
        contract_address: ContractAddress,
        input: JsonBytes,
    ) -> Result<TransactionReceipt>;

    #[rpc(name = "create")]
    fn create(&self, sender: EoaAddress, code: JsonBytes) -> Result<TransactionReceipt>;
}

pub struct RpcImpl {
    pub loader: Arc<Loader>,
    pub run_config: RunConfig,
}

impl Rpc for RpcImpl {
    fn get_code(&self, contract_address: ContractAddress) -> Result<ContractCodeJson> {
        let code = self
            .loader
            .load_contract_code(contract_address)
            .map_err(convert_err)?;
        Ok(code.into())
    }

    fn get_change(
        &self,
        contract_address: ContractAddress,
        block_number: Option<u64>,
    ) -> Result<ContractChangeJson> {
        self.loader
            .load_latest_contract_change(contract_address, block_number, true)
            .map(ContractChangeJson::from)
            .map_err(convert_err)
    }

    fn static_call(
        &self,
        sender: EoaAddress,
        contract_address: ContractAddress,
        input: JsonBytes,
    ) -> Result<JsonBytes> {
        let loader = Loader::clone(&self.loader);
        let run_config = self.run_config.clone();
        Runner::new(loader, run_config)
            .static_call(sender, contract_address, input.into_bytes())
            .map(JsonBytes::from_bytes)
            .map_err(convert_err_box)
    }

    fn call(
        &self,
        sender: EoaAddress,
        contract_address: ContractAddress,
        input: JsonBytes,
    ) -> Result<TransactionReceipt> {
        let loader = Loader::clone(&self.loader);
        let run_config = self.run_config.clone();
        Runner::new(loader, run_config)
            .call(sender, contract_address, input.into_bytes())
            .map_err(convert_err_box)
    }

    fn create(&self, sender: EoaAddress, code: JsonBytes) -> Result<TransactionReceipt> {
        let loader = Loader::clone(&self.loader);
        let run_config = self.run_config.clone();
        Runner::new(loader, run_config)
            .create(sender, code.into_bytes())
            .map_err(convert_err_box)
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
pub struct ContractChangeJson {
    pub sender: EoaAddress,
    pub address: ContractAddress,
    /// Block number
    pub number: u64,
    /// Transaction index in current block
    pub tx_index: u32,
    /// Output index in current transaction
    pub output_index: u32,
    pub tx_hash: H256,
    pub new_storage: Vec<(H256, H256)>,
    pub logs: Vec<(Vec<H256>, JsonBytes)>,
    /// The change is create the contract
    pub is_create: bool,
}

impl From<ContractChange> for ContractChangeJson {
    fn from(change: ContractChange) -> ContractChangeJson {
        ContractChangeJson {
            sender: change.sender,
            address: change.address,
            number: change.number,
            tx_index: change.tx_index,
            output_index: change.output_index,
            tx_hash: change.tx_hash,
            new_storage: change.new_storage.into_iter().collect::<Vec<_>>(),
            logs: change
                .logs
                .into_iter()
                .map(|(topics, data)| (topics, JsonBytes::from_bytes(data)))
                .collect::<Vec<_>>(),
            is_create: change.is_create,
        }
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
