use bincode::deserialize;
use ckb_jsonrpc_types as json_types;
use ckb_types::{
    bytes::Bytes,
    core::{BlockView, EpochNumberWithFraction, HeaderView, ScriptHashType},
    packed,
    prelude::*,
    H160, H256, U256,
};
use rocksdb::DB;
use std::collections::HashSet;
use std::convert::TryFrom;
use std::sync::Arc;

use super::{db_get, value, Key};
use crate::client::HttpRpcClient;
use crate::types::{
    ContractAddress, ContractChange, ContractMeta, EoaAddress, LogInfo, CELLBASE_MATURITY,
    SIGHASH_TYPE_HASH,
};

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

    pub fn load_contract_live_cell(
        &mut self,
        tx_hash: H256,
        output_index: u32,
    ) -> Result<(packed::CellOutput, Bytes), String> {
        let out_point = json_types::OutPoint {
            tx_hash: tx_hash.clone(),
            index: json_types::Uint32::from(output_index),
        };
        let cell_with_status = self.client.get_live_cell(out_point, true)?;
        let cell = cell_with_status.cell.ok_or_else(|| {
            format!(
                "contract cell is not live cell, tx_hash={:x}, output_index={}",
                tx_hash, output_index
            )
        })?;
        Ok((cell.output.into(), cell.data.unwrap().content.into_bytes()))
    }

    pub fn load_eoa_live_cell(
        &mut self,
        eoa_address: H160,
    ) -> Result<(value::EoaLiveCell, packed::CellOutput, Bytes), String> {
        let key_bytes = Bytes::from(&Key::EoaLiveCell(eoa_address.clone()));
        let value = db_get::<_, value::EoaLiveCell>(&self.db, &key_bytes)?
            .ok_or_else(|| format!("eoa live cell not found: {:x}", eoa_address))?;
        let cell_with_status = self.client.get_live_cell(value.out_point().into(), true)?;
        let cell = cell_with_status.cell.ok_or_else(|| {
            format!(
                "eoa cell is not live cell, tx_hash={:x}, output_index={}",
                value.tx_hash, value.output_index
            )
        })?;
        Ok((
            value,
            cell.output.into(),
            cell.data.unwrap().content.into_bytes(),
        ))
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
                if !is_mature(max_mature_number, number, tx_index)
                    || value.type_script_hash.is_some()
                    || value.data_size > 0
                {
                    // Ignore:
                    //   * immature cells
                    //   * cell with type script
                    //   * cell with output data
                    iter.next();
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

        if total_capacity < min_capacity {
            Err(format!(
                "Not enough live cells: sender: {:x}, total capacity = {}",
                sender.0, total_capacity
            ))
        } else {
            Ok((live_cells, total_capacity))
        }
    }

    pub fn load_latest_contract_change(
        &self,
        address: ContractAddress,
        block_number: Option<u64>,
        load_logs: bool,
        check_alive: bool,
    ) -> Result<ContractChange, String> {
        if check_alive {
            let meta = self.load_contract_meta(address.clone())?;
            if meta.destructed {
                return Err(format!("Contract already destructed: {:x}", address.0));
            }
        }
        let prefix_key = Key::ContractChange {
            address: address.clone(),
            number: None,
            tx_index: None,
            output_index: None,
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
                tx_origin: value.tx_origin,
                address,
                tx_hash: value.tx_hash,
                new_storage: value.new_storage.into_iter().collect(),
                capacity: value.capacity,
                balance: value.balance,
                is_create: value.is_create,
                number,
                tx_index,
                output_index,
                logs,
            });
        }
        Err(String::from("Latest contract change not found"))
    }

    pub fn load_contract_meta_list(
        &mut self,
        from_block: u64,
        to_block: Option<u64>,
    ) -> Result<Vec<(u64, ContractMeta)>, String> {
        let to_block = to_block
            .map(Ok)
            .unwrap_or_else(|| self.client.get_tip_block_number())?;

        let mut all_metas = Vec::new();
        for number in from_block..=to_block {
            let key_bytes = Bytes::from(&Key::BlockDelta(number));
            let block_delta = match db_get::<_, value::BlockDelta>(&self.db, &key_bytes)? {
                Some(block_delta) => block_delta,
                None => {
                    return Ok(all_metas);
                }
            };
            for addr in block_delta
                .contracts
                .into_iter()
                .filter(|(_, is_create)| *is_create)
                .map(|(addr, _)| addr)
            {
                let key_bytes = Bytes::from(&Key::ContractMeta(addr.clone()));
                let meta = db_get::<_, value::ContractMeta>(&self.db, &key_bytes)?.unwrap();
                all_metas.push((
                    number,
                    ContractMeta {
                        address: addr.clone(),
                        code: meta.code,
                        tx_hash: meta.tx_hash,
                        output_index: meta.output_index,
                        balance: meta.balance,
                        destructed: meta.destructed,
                    },
                ));
            }
        }
        Ok(all_metas)
    }

    pub fn load_contract_meta(&self, address: ContractAddress) -> Result<ContractMeta, String> {
        let key_bytes = Bytes::from(&Key::ContractMeta(address.clone()));
        if let Some(value) = db_get::<_, value::ContractMeta>(&self.db, &key_bytes)? {
            Ok(ContractMeta {
                address,
                code: value.code,
                tx_hash: value.tx_hash,
                output_index: value.output_index,
                balance: value.balance,
                destructed: value.destructed,
            })
        } else {
            Err(format!("Contract meta not found: {}", address.0))
        }
    }

    pub fn load_logs(
        &mut self,
        from_block: u64,
        to_block: Option<u64>,
        address: Option<ContractAddress>,
        filter_topics: Option<Vec<H256>>,
        limit: Option<u32>,
    ) -> Result<Vec<LogInfo>, String> {
        let to_block = to_block
            .map(Ok)
            .unwrap_or_else(|| self.client.get_tip_block_number())?;
        let filter_topics = filter_topics.map(|topics| topics.into_iter().collect::<HashSet<_>>());

        let mut all_logs = Vec::new();
        for number in from_block..=to_block {
            let key_bytes = Bytes::from(&Key::BlockDelta(number));
            let block_delta = match db_get::<_, value::BlockDelta>(&self.db, &key_bytes)? {
                Some(block_delta) => block_delta,
                None => {
                    return Ok(all_logs);
                }
            };
            for (addr, _is_create) in block_delta.contracts {
                if let Some(target_address) = address.as_ref() {
                    if &addr != target_address {
                        continue;
                    }
                }
                let key_prefix_bytes = Bytes::from(&Key::ContractLogs {
                    address: addr.clone(),
                    number: Some(number),
                    tx_index: None,
                    output_index: None,
                });
                let mut iter = self.db.raw_iterator();
                iter.seek(&key_prefix_bytes);
                while iter.valid() {
                    if let Some((key_bytes, value_bytes)) = iter
                        .key()
                        .filter(|key| key.starts_with(&key_prefix_bytes))
                        .and_then(|key| iter.value().map(|value| (key, value)))
                    {
                        let value: value::ContractLogs =
                            deserialize(value_bytes).map_err(|err| err.to_string())?;
                        let tx_index = match Key::try_from(key_bytes)? {
                            Key::ContractLogs { tx_index, .. } => tx_index.unwrap(),
                            _ => {
                                panic!("DB corrupted deserialize Key::ContractChange");
                            }
                        };
                        for (topics, data) in value.0.into_iter().filter(|(topics, _)| {
                            filter_topics
                                .as_ref()
                                .map(|filter_topics| {
                                    topics.iter().any(|topic| filter_topics.contains(topic))
                                })
                                .unwrap_or(true)
                        }) {
                            if all_logs.len() >= limit.unwrap_or(std::u32::MAX) as usize {
                                return Ok(all_logs);
                            }
                            all_logs.push(LogInfo {
                                block_number: number,
                                tx_index,
                                address: addr.clone(),
                                topics,
                                data,
                            });
                        }
                    } else {
                        break;
                    }
                    iter.next();
                }
            }
        }
        Ok(all_logs)
    }

    pub fn load_header_deps(&mut self, inputs: &[packed::CellInput]) -> Result<Vec<H256>, String> {
        inputs
            .iter()
            .map(|input| {
                let tx_hash = Unpack::<H256>::unpack(&input.previous_output().tx_hash());
                self.client
                    .get_transaction(tx_hash.clone())?
                    .ok_or_else(|| format!("Transaction not found for input: {:?}", input))?
                    .tx_status
                    .block_hash
                    .ok_or_else(|| format!("Transaction not committed: {:x}", tx_hash))
            })
            .collect()
    }

    pub fn load_header(&mut self, number_opt: Option<u64>) -> Result<HeaderView, String> {
        let header = if let Some(number) = number_opt {
            self.client
                .get_header_by_number(number)?
                .ok_or_else(|| format!("Block #{} not exists", number))?
        } else {
            self.client.get_tip_header()?
        };
        Ok(HeaderView::from(header))
    }

    pub fn load_block(&mut self, hash_opt: Option<H256>) -> Result<BlockView, String> {
        let hash = if let Some(hash) = hash_opt {
            hash
        } else {
            self.client.get_tip_header()?.hash
        };
        self.client
            .get_block(hash.clone())?
            .ok_or_else(|| format!("Block 0x{:x} not exists", hash))
            .map(BlockView::from)
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
