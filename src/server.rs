use crate::storage::{CsalRunContext, Loader, Runner};
use crate::types::{
    parse_log, ContractAddress, ContractChange, ContractMeta, EoaAddress, RunConfig,
};
use ckb_hash::blake2b_256;
use ckb_jsonrpc_types::{JsonBytes, Transaction};
use ckb_types::{bytes::Bytes, H256};
use jsonrpc_core::{Error, ErrorCode, Result as RpcResult};
use jsonrpc_derive::rpc;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::error::Error as StdError;
use std::sync::Arc;

#[rpc(server)]
pub trait Rpc {
    #[rpc(name = "create")]
    fn create(&self, sender: EoaAddress, code: JsonBytes) -> RpcResult<TransactionReceipt>;

    #[rpc(name = "call")]
    fn call(
        &self,
        sender: EoaAddress,
        contract_address: ContractAddress,
        input: JsonBytes,
    ) -> RpcResult<TransactionReceipt>;

    #[rpc(name = "static_call")]
    fn static_call(
        &self,
        sender: EoaAddress,
        contract_address: ContractAddress,
        input: JsonBytes,
    ) -> RpcResult<StaticCallResponse>;

    #[rpc(name = "get_code")]
    fn get_code(&self, contract_address: ContractAddress) -> RpcResult<ContractCodeJson>;

    #[rpc(name = "get_contracts")]
    fn get_contracts(
        &self,
        from_block: u64,
        to_block: Option<u64>,
    ) -> RpcResult<Vec<ContractMetaJson>>;

    #[rpc(name = "get_change")]
    fn get_change(
        &self,
        contract_address: ContractAddress,
        block_number: Option<u64>,
    ) -> RpcResult<ContractChangeJson>;

    #[rpc(name = "get_logs")]
    fn get_logs(
        &self,
        from_block: u64,
        to_block: Option<u64>,
        address: Option<ContractAddress>,
        filter_topics: Option<Vec<H256>>,
        limit: Option<u32>,
    ) -> RpcResult<Vec<LogInfo>>;
}

pub struct RpcImpl {
    pub loader: Arc<Loader>,
    pub run_config: RunConfig,
}

impl Rpc for RpcImpl {
    fn create(&self, sender: EoaAddress, code: JsonBytes) -> RpcResult<TransactionReceipt> {
        let loader = Loader::clone(&self.loader);
        let run_config = self.run_config.clone();
        let (contract_address, tx, result, context) = Runner::new(loader, run_config)
            .create(sender, code.into_bytes())
            .map_err(convert_err_box)?;

        let logs = context
            .logs
            .into_iter()
            .map(|log_data| {
                parse_log(log_data.as_ref())
                    .map(|(topics, data)| LogEntry::new(contract_address.clone(), topics, data))
            })
            .collect::<Result<Vec<_>, String>>()
            .map_err(convert_err)?;
        Ok(TransactionReceipt {
            tx: Transaction::from(tx),
            contract_address: Some(contract_address),
            return_data: Some(JsonBytes::from_bytes(context.return_data)),
            logs,
        })
    }

    fn call(
        &self,
        sender: EoaAddress,
        contract_address: ContractAddress,
        input: JsonBytes,
    ) -> RpcResult<TransactionReceipt> {
        let loader = Loader::clone(&self.loader);
        let run_config = self.run_config.clone();
        let (tx, result, context) = Runner::new(loader, run_config)
            .call(sender, contract_address.clone(), input.into_bytes())
            .map_err(convert_err_box)?;

        let logs = context
            .logs
            .into_iter()
            .map(|log_data| {
                parse_log(log_data.as_ref())
                    .map(|(topics, data)| LogEntry::new(contract_address.clone(), topics, data))
            })
            .collect::<Result<Vec<_>, String>>()
            .map_err(convert_err)?;
        Ok(TransactionReceipt {
            tx: Transaction::from(tx),
            contract_address: None,
            return_data: Some(JsonBytes::from_bytes(context.return_data)),
            logs,
        })
    }

    fn static_call(
        &self,
        sender: EoaAddress,
        contract_address: ContractAddress,
        input: JsonBytes,
    ) -> RpcResult<StaticCallResponse> {
        let loader = Loader::clone(&self.loader);
        let run_config = self.run_config.clone();
        let (_result, context) = Runner::new(loader, run_config)
            .static_call(sender, contract_address.clone(), input.into_bytes())
            .map_err(convert_err_box)?;
        StaticCallResponse::try_from((context, contract_address)).map_err(convert_err)
    }

    fn get_code(&self, contract_address: ContractAddress) -> RpcResult<ContractCodeJson> {
        self.loader
            .load_contract_meta(contract_address)
            .map(ContractCodeJson::from)
            .map_err(convert_err)
    }

    fn get_contracts(
        &self,
        from_block: u64,
        to_block: Option<u64>,
    ) -> RpcResult<Vec<ContractMetaJson>> {
        let mut loader = Loader::clone(&self.loader);
        loader
            .load_contract_meta_list(from_block, to_block)
            .map(|metas| {
                metas
                    .into_iter()
                    .map(|(number, meta)| ContractMetaJson::new(number, meta))
                    .collect::<Vec<_>>()
            })
            .map_err(convert_err)
    }

    fn get_change(
        &self,
        contract_address: ContractAddress,
        block_number: Option<u64>,
    ) -> RpcResult<ContractChangeJson> {
        self.loader
            .load_latest_contract_change(contract_address, block_number, true, true)
            .map(ContractChangeJson::from)
            .map_err(convert_err)
    }

    fn get_logs(
        &self,
        from_block: u64,
        to_block: Option<u64>,
        address: Option<ContractAddress>,
        filter_topics: Option<Vec<H256>>,
        limit: Option<u32>,
    ) -> RpcResult<Vec<LogInfo>> {
        let mut loader = Loader::clone(&self.loader);
        loader
            .load_logs(from_block, to_block, address, filter_topics, limit)
            .map(|logs| {
                logs.into_iter()
                    .map(|info| {
                        let log = LogEntry::new(info.address, info.topics, info.data);
                        LogInfo {
                            block_number: info.block_number,
                            tx_index: info.tx_index,
                            log,
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .map_err(convert_err)
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
impl From<ContractMeta> for ContractCodeJson {
    fn from(meta: ContractMeta) -> ContractCodeJson {
        ContractCodeJson {
            code: JsonBytes::from_bytes(meta.code),
            tx_hash: meta.tx_hash,
            output_index: meta.output_index,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogInfo {
    block_number: u64,
    tx_index: u32,
    log: LogEntry,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    address: ContractAddress,
    topics: Vec<H256>,
    data: JsonBytes,
}

impl LogEntry {
    pub fn new(address: ContractAddress, topics: Vec<H256>, data: Bytes) -> LogEntry {
        LogEntry {
            address,
            topics,
            data: JsonBytes::from_bytes(data),
        }
    }
}

/// The transaction receipt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionReceipt {
    pub tx: Transaction,
    /// The newly created contract's address (Program.depth=0)
    pub contract_address: Option<ContractAddress>,
    pub return_data: Option<JsonBytes>,
    pub logs: Vec<LogEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticCallResponse {
    return_data: JsonBytes,
    logs: Vec<LogEntry>,
}

impl TryFrom<(CsalRunContext, ContractAddress)> for StaticCallResponse {
    type Error = String;
    fn try_from(
        (context, contract_address): (CsalRunContext, ContractAddress),
    ) -> Result<StaticCallResponse, String> {
        Ok(StaticCallResponse {
            return_data: JsonBytes::from_bytes(context.return_data),
            logs: context
                .logs
                .into_iter()
                .map(|log_data| {
                    parse_log(log_data.as_ref())
                        .map(|(topics, data)| LogEntry::new(contract_address.clone(), topics, data))
                })
                .collect::<Result<Vec<_>, String>>()?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractMetaJson {
    /// The block where the contract created
    pub block_number: u64,
    /// The contract address
    pub address: ContractAddress,

    /// The contract code
    pub code: JsonBytes,
    /// The contract code hash
    pub code_hash: H256,
    /// The hash of the transaction where the contract created
    pub tx_hash: H256,
    /// The output index of the transaction where the contract created
    pub output_index: u32,
    /// Check if the contract is destructed
    pub destructed: bool,
}

impl ContractMetaJson {
    pub fn new(block_number: u64, meta: ContractMeta) -> ContractMetaJson {
        let code_hash = H256::from_slice(&blake2b_256(meta.code.as_ref())[..]).unwrap();
        ContractMetaJson {
            block_number,
            address: meta.address,
            code: JsonBytes::from_bytes(meta.code),
            code_hash,
            tx_hash: meta.tx_hash,
            output_index: meta.output_index,
            destructed: meta.destructed,
        }
    }
}
