use bincode::deserialize;
use ckb_types::{
    bytes::Bytes,
    core::{EpochNumberWithFraction, ScriptHashType},
    packed,
    prelude::*,
    H160, H256, U256,
};
use rocksdb::DB;
use std::convert::TryFrom;
use std::sync::Arc;

use super::{db_get, value, Key};
use crate::client::HttpRpcClient;
use crate::types::{
    ContractAddress, ContractChange, ContractCode, EoaAddress, LogEntry, CELLBASE_MATURITY,
    SIGHASH_TYPE_HASH,
};

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

#[derive(Clone)]
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

    pub fn collect_cells(
        &mut self,
        sender: EoaAddress,
        min_capacity: u64,
    ) -> Result<(Vec<packed::OutPoint>, u64), String> {
        let lock_hash: H256 = packed::Script::new_builder()
            .code_hash(SIGHASH_TYPE_HASH.pack())
            .hash_type(ScriptHashType::Type.into())
            .args(Bytes::from(sender.0.as_bytes().to_vec()).pack())
            .build()
            .calc_script_hash()
            .unpack();
        let key_prefix_bytes = Bytes::from(&Key::LockLiveCell {
            lock_hash,
            number: None,
            tx_index: None,
            output_index: None,
        });

        let max_mature_number = get_max_mature_number(&mut self.client)?;
        let mut total_capacity: u64 = 0;
        let mut live_cells = Vec::new();

        let mut iter = self.db.raw_iterator();
        iter.seek(&key_prefix_bytes);
        while iter.valid() {
            if let Some((key_bytes, value_bytes)) = iter
                .key()
                .filter(|key| key.starts_with(&key_prefix_bytes))
                .and_then(|key| iter.value().map(|value| (key, value)))
            {
                let value: value::LockLiveCell =
                    deserialize(value_bytes).map_err(|err| err.to_string())?;
                let (_lock_hash, number, tx_index, _output_index) = match Key::try_from(key_bytes)?
                {
                    Key::LockLiveCell {
                        lock_hash,
                        number,
                        tx_index,
                        output_index,
                    } => (
                        lock_hash,
                        number.expect("illegal key"),
                        tx_index.expect("illegal key"),
                        output_index.expect("illegal key"),
                    ),
                    _ => {
                        panic!("DB corrupted deserialize Key::LockLiveCell");
                    }
                };
                if !is_mature(max_mature_number, number, tx_index) {
                    // Ignore immature cells
                    continue;
                }
                live_cells.push(value.out_point());
                total_capacity += value.capacity;
                if total_capacity >= min_capacity {
                    break;
                }
            } else {
                break;
            }
            iter.next();
        }
        Ok((live_cells, total_capacity))
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
            let value: value::ContractChange =
                deserialize(value_bytes).map_err(|err| err.to_string())?;
            let (address, number, tx_index, output_index) = match Key::try_from(key_bytes)? {
                Key::ContractChange {
                    address,
                    number,
                    tx_index,
                    output_index,
                } => (
                    address,
                    number.expect("illegal key"),
                    tx_index.expect("illegal key"),
                    output_index.expect("illegal key"),
                ),
                _ => {
                    panic!("DB corrupted deserialize Key::ContractChange");
                }
            };
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
        }
        Err(String::from("Latest contract change not found"))
    }

    pub fn load_contract_changes(
        &self,
        address: ContractAddress,
        from_block: Option<u64>,
        to_block: Option<u64>,
    ) -> Result<Vec<ContractChange>, String> {
        Err(String::from("TODO: Loader::load_contract_changes"))
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
        Err(String::from("TODO: Loader::load_logs"))
    }
}

// Get max mature block number
pub fn get_max_mature_number(client: &mut HttpRpcClient) -> Result<u64, String> {
    let tip_epoch = client
        .get_tip_header()
        .map(|header| EpochNumberWithFraction::from_full_value(header.inner.epoch.value()))?;
    let tip_epoch_number = tip_epoch.number();
    if tip_epoch_number < 4 {
        // No cellbase live cell is mature
        Ok(0)
    } else {
        let max_mature_epoch = client
            .get_epoch_by_number(tip_epoch_number - 4)?
            .ok_or_else(|| "Can not get epoch less than current epoch number".to_string())?;
        let start_number = max_mature_epoch.start_number;
        let length = max_mature_epoch.length;
        Ok(calc_max_mature_number(
            tip_epoch,
            Some((start_number.value(), length.value())),
            CELLBASE_MATURITY,
        ))
    }
}

// Calculate max mature block number
pub fn calc_max_mature_number(
    tip_epoch: EpochNumberWithFraction,
    max_mature_epoch: Option<(u64, u64)>,
    cellbase_maturity: EpochNumberWithFraction,
) -> u64 {
    if tip_epoch.to_rational() < cellbase_maturity.to_rational() {
        0
    } else if let Some((start_number, length)) = max_mature_epoch {
        let epoch_delta = tip_epoch.to_rational() - cellbase_maturity.to_rational();
        let index_bytes: [u8; 32] = ((epoch_delta.clone() - epoch_delta.into_u256())
            * U256::from(length))
        .into_u256()
        .to_le_bytes();
        let mut index_bytes_u64 = [0u8; 8];
        index_bytes_u64.copy_from_slice(&index_bytes[0..8]);
        u64::from_le_bytes(index_bytes_u64) + start_number
    } else {
        0
    }
}

pub fn is_mature(max_mature_number: u64, number: u64, tx_index: u32) -> bool {
    // Not cellbase cell
    tx_index > 0
    // Live cells in genesis are all mature
        || number == 0
        || number <= max_mature_number
}
