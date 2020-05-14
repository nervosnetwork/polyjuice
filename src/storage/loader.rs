use bincode::{deserialize, serialize};
use ckb_types::{bytes::Bytes, H160, H256};
use rocksdb::DB;
use std::convert::TryFrom;
use std::sync::Arc;

use super::{db_get, value, Key};
use crate::rpc_client::HttpRpcClient;
use crate::types::{ContractAddress, ContractChange, ContractCode, LogEntry};

// Query Interface
// ===============
// ## Contract Account
//     * getBalance(addr: ContractAddress, number: Option<BlockNumber>)
//           -> Capacity
//     * getStorageAt(addr: ContractAddress, position: U256, number: Option<BlockNumber>)
//           -> U256
//     * getCode(addr: ContractAddress)
//           -> (Bytes, OutPoint)
//     * call(addr: ContractAddress, input_data: Bytes)
//           -> Bytes
// ## Transaction
//     * generateTransaction(addr: Option<ContractAddress>, input_data: Bytes)
//           -> CkbTransaction
//     * sendRawTransaction(tx: CkbTransaction)
//           -> H256
//     * getTransactionByHash(tx_hash: H256)
//           -> CkbTransaction
//     * getTransactionReceipt(tx_hash: H256)
//           -> TransactionReceipt
//     * getLogs(filter: LogFilter)
//               -> Vec<LogEntry>

pub struct Loader {
    pub db: Arc<DB>,
    client: HttpRpcClient,
}

impl Loader {
    pub fn new(db: Arc<DB>, ckb_uri: &str) -> Result<Loader, String> {
        Ok(Loader {
            db,
            client: HttpRpcClient::new(ckb_uri.to_string()),
        })
    }

    pub fn load_latest_contract_change(
        &self,
        address: ContractAddress,
        block_number: Option<u64>,
        load_logs: bool,
    ) -> Result<ContractChange, String> {
        let prefix_key = if let Some(number) = block_number {
            Key::ContractChange {
                address: address.clone(),
                number: Some(number),
                tx_index: None,
                output_index: None,
            }
        } else {
            Key::ContractChange {
                address: address.clone(),
                number: None,
                tx_index: None,
                output_index: None,
            }
        };
        let prefix_key_bytes = Bytes::from(&prefix_key);

        let next_block_number = block_number
            .map(|number| number + 1)
            .unwrap_or(std::u64::MAX);
        let last_key = Key::ContractChange {
            address,
            number: Some(next_block_number),
            tx_index: None,
            output_index: None,
        };

        let mut iter = self.db.raw_iterator();
        iter.seek_for_prev(&Bytes::from(&last_key));
        let is_valid = iter.valid();
        if let Some((key_bytes, value_bytes)) = iter
            .key()
            .filter(|key| is_valid && key.starts_with(&prefix_key_bytes))
            .and_then(|key| iter.value().map(|value| (key, value)))
        {
            let key = Key::try_from(key_bytes)?;
            let value: value::ContractChange =
                deserialize(value_bytes).map_err(|err| err.to_string())?;
            if let Key::ContractChange {
                address,
                number,
                tx_index,
                output_index,
            } = key
            {
                let number = number.expect("illegal key");
                let tx_index = tx_index.expect("illegal key");
                let output_index = output_index.expect("illegal key");
                let logs = if load_logs {
                    let logs_key_bytes = Bytes::from(&Key::ContractLogs {
                        address: address.clone(),
                        number: Some(number),
                        tx_index: Some(tx_index),
                        output_index: Some(output_index),
                    });
                    db_get(&self.db, &logs_key_bytes)?
                        .map(|logs: value::ContractLogs| logs.0)
                        .unwrap_or_default()
                } else {
                    Vec::new()
                };
                return Ok(ContractChange {
                    sender: value.sender,
                    address,
                    tx_hash: value.tx_hash,
                    new_storage: value.new_storage.into_iter().collect(),
                    is_create: value.is_create,
                    number,
                    tx_index,
                    output_index,
                    logs,
                });
            } else {
                panic!("DB corrupted deserialize ContractChange");
            }
        }
        Err(String::from("Latest contract change not found"))
    }

    pub fn load_contract_changes(
        &self,
        address: ContractAddress,
        from_block: Option<u64>,
        to_block: Option<u64>,
    ) -> Result<Vec<ContractChange>, String> {
        Err(String::from("TODO"))
    }

    pub fn load_contract_code(&self, address: ContractAddress) -> Result<ContractCode, String> {
        let key_bytes = Bytes::from(&Key::ContractCode(address.clone()));
        if let Some(value) = db_get::<_, value::ContractCode>(&self.db, &key_bytes)? {
            Ok(ContractCode {
                address,
                code: value.code,
                tx_hash: value.tx_hash,
                output_index: value.output_index,
            })
        } else {
            Err(format!("Contract code not found: {:?}", address))
        }
    }

    pub fn load_logs(
        &self,
        from_block: u64,
        to_block: u64,
        _block_hash: Option<H256>,
        address: Option<H160>,
        filter_topics: Option<Vec<H256>>,
        _limit: Option<usize>,
    ) -> Result<Vec<LogEntry>, String> {
        Err(String::from("TODO"))
    }
}
