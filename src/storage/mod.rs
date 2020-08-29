mod indexer;
mod loader;
mod runner;

pub use indexer::Indexer;
pub use loader::Loader;
pub use runner::{CsalRunContext, Runner};

use crate::types::ContractAddress;
use bincode::deserialize;
use ckb_types::{bytes::Bytes, packed, prelude::*, H160, H256};
use rocksdb::DB;
use serde::de::DeserializeOwned;
use std::convert::TryFrom;
use std::mem;

type BlockNumber = u64;

/// The indexer key type
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
#[repr(u8)]
pub enum KeyType {
    /// The key is just last
    ///   "last" => (BlockNumber, BlockHash)
    Last = 0x00,

    /// The key is a block number
    ///   BlockNumber => BlockHash
    BlockMap = 0x01,

    /// Contract state change
    ///   (ContractAddress, BlockNumber, TransactionIndex, OutputIndex)
    ///      => (TransactionHash, SenderAddress, NewStorageTree)
    ContractChange = 0x02,

    /// Contract logs
    ///   (ContractAddress, BlockNumber, TransactionIndex, OutputIndex)
    ///      => Vec<(Topics, Data)>
    ContractLogs = 0x03,

    /// Contract metadata
    ///   ContractAddress => (Code, OutPoint, destructed)
    ContractMeta = 0x04,

    /// Live Cell indexed by lock script hash
    ///   (LockHash, BlockNumber, TransactionIndex, OutputIndex)
    ///      => (TransactionHash, OutputIndex)
    LockLiveCell = 0x05,

    /// Store meta info of a live cell outpoint
    ///   OutPoint => (BlockNumber, TransactionIndex)
    LiveCellMap = 0x06,

    /// Delta in the block (for rollback)
    ///   BlockNumber => value::BlockDelta
    BlockDelta = 0xF0,
}

impl TryFrom<u8> for KeyType {
    type Error = String;
    fn try_from(value: u8) -> Result<KeyType, String> {
        match value {
            0x00 => Ok(KeyType::Last),
            0x01 => Ok(KeyType::BlockMap),
            0x02 => Ok(KeyType::ContractChange),
            0x03 => Ok(KeyType::ContractLogs),
            0x04 => Ok(KeyType::ContractMeta),
            0x05 => Ok(KeyType::LockLiveCell),
            0x06 => Ok(KeyType::LiveCellMap),
            0xF0 => Ok(KeyType::BlockDelta),
            _ => Err(format!("Invalid KeyType {}", value)),
        }
    }
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum Key {
    Last,
    BlockMap(BlockNumber),
    ContractChange {
        address: ContractAddress,
        number: Option<BlockNumber>,
        /// Transaction index in current block
        tx_index: Option<u32>,
        /// Output index in current transaction
        output_index: Option<u32>,
    },
    ContractLogs {
        address: ContractAddress,
        number: Option<BlockNumber>,
        /// Transaction index in current block
        tx_index: Option<u32>,
        /// Output index in current transaction
        output_index: Option<u32>,
    },
    ContractMeta(ContractAddress),
    LockLiveCell {
        lock_hash: H256,
        number: Option<BlockNumber>,
        /// Transaction index in current block
        tx_index: Option<u32>,
        /// Output index in current transaction
        output_index: Option<u32>,
    },
    LiveCellMap(packed::OutPoint),
    BlockDelta(BlockNumber),
}

impl From<&Key> for Bytes {
    fn from(key: &Key) -> Bytes {
        fn serialize_output_pos(
            bytes: &mut Vec<u8>,
            number: Option<u64>,
            tx_index: Option<u32>,
            output_index: Option<u32>,
        ) {
            if let Some(number) = number {
                bytes.extend(&number.to_be_bytes());
                if let Some(tx_index) = tx_index {
                    bytes.extend(&tx_index.to_be_bytes());
                    if let Some(output_index) = output_index {
                        bytes.extend(&output_index.to_be_bytes());
                    }
                }
            }
        }
        fn serialize_record_key(
            key_type: KeyType,
            address: &ContractAddress,
            number: Option<u64>,
            tx_index: Option<u32>,
            output_index: Option<u32>,
        ) -> Bytes {
            let mut bytes = vec![key_type as u8];
            bytes.extend(address.0.as_bytes());
            serialize_output_pos(&mut bytes, number, tx_index, output_index);
            bytes.into()
        }
        match key {
            Key::Last => vec![KeyType::Last as u8].into(),
            Key::BlockMap(number) => {
                let mut bytes = vec![KeyType::BlockMap as u8];
                bytes.extend(&number.to_be_bytes());
                bytes.into()
            }
            Key::ContractChange {
                address,
                number,
                tx_index,
                output_index,
            } => serialize_record_key(
                KeyType::ContractChange,
                address,
                *number,
                *tx_index,
                *output_index,
            ),
            Key::ContractLogs {
                address,
                number,
                tx_index,
                output_index,
            } => serialize_record_key(
                KeyType::ContractLogs,
                address,
                *number,
                *tx_index,
                *output_index,
            ),
            Key::ContractMeta(address) => {
                let mut bytes = vec![KeyType::ContractMeta as u8];
                bytes.extend(address.0.as_bytes());
                bytes.into()
            }
            Key::LockLiveCell {
                lock_hash,
                number,
                tx_index,
                output_index,
            } => {
                let mut bytes = vec![KeyType::LockLiveCell as u8];
                bytes.extend(lock_hash.as_bytes());
                serialize_output_pos(&mut bytes, *number, *tx_index, *output_index);
                bytes.into()
            }
            Key::LiveCellMap(out_point) => {
                let mut bytes = vec![KeyType::LiveCellMap as u8];
                bytes.extend(out_point.as_slice());
                bytes.into()
            }
            Key::BlockDelta(number) => {
                let mut bytes = vec![KeyType::BlockDelta as u8];
                bytes.extend(&number.to_be_bytes());
                bytes.into()
            }
        }
    }
}

impl TryFrom<&[u8]> for Key {
    type Error = String;
    fn try_from(data: &[u8]) -> Result<Key, String> {
        fn ensure_content_len(name: &str, content: &[u8], expected: usize) -> Result<(), String> {
            if content.len() != expected {
                Err(format!(
                    "Invalid Key::{} content length: {}",
                    name,
                    content.len()
                ))
            } else {
                Ok(())
            }
        }
        fn deserialize_u64(content: &[u8]) -> u64 {
            let mut number_bytes = [0u8; 8];
            number_bytes.copy_from_slice(content);
            u64::from_be_bytes(number_bytes)
        }
        fn deserialize_u32(content: &[u8]) -> u32 {
            let mut number_bytes = [0u8; 4];
            number_bytes.copy_from_slice(content);
            u32::from_be_bytes(number_bytes)
        }
        fn deserialize_record_key(
            name: &str,
            content: &[u8],
        ) -> Result<(ContractAddress, u64, u32, u32), String> {
            const EXPECTED: usize = mem::size_of::<H160>()
                + mem::size_of::<BlockNumber>()
                + mem::size_of::<u32>()
                + mem::size_of::<u32>();
            assert_eq!(EXPECTED, 20 + 8 + 4 + 4);
            ensure_content_len(name, content, EXPECTED)?;

            let address = ContractAddress::from(
                H160::from_slice(&content[0..20]).expect("deserialize address"),
            );
            let number = deserialize_u64(&content[20..28]);
            let tx_index = deserialize_u32(&content[28..32]);
            let output_index = deserialize_u32(&content[32..36]);
            Ok((address, number, tx_index, output_index))
        }

        if data.is_empty() {
            return Err(String::from("Can't convert to Key from empty data"));
        }
        let key_type = KeyType::try_from(data[0])?;
        let content = &data[1..];
        match key_type {
            KeyType::Last => Ok(Key::Last),
            KeyType::BlockMap => {
                ensure_content_len("BlockMap", content, mem::size_of::<BlockNumber>())?;
                let number = deserialize_u64(content);
                Ok(Key::BlockMap(number))
            }
            KeyType::ContractChange => {
                let (address, number, tx_index, output_index) =
                    deserialize_record_key("ContractChange", content)?;
                Ok(Key::ContractChange {
                    address,
                    number: Some(number),
                    tx_index: Some(tx_index),
                    output_index: Some(output_index),
                })
            }
            KeyType::ContractLogs => {
                let (address, number, tx_index, output_index) =
                    deserialize_record_key("ContractLogs", content)?;
                Ok(Key::ContractLogs {
                    address,
                    number: Some(number),
                    tx_index: Some(tx_index),
                    output_index: Some(output_index),
                })
            }
            KeyType::ContractMeta => {
                ensure_content_len("ContractMeta", content, mem::size_of::<H160>())?;
                let address = ContractAddress::from(
                    H160::from_slice(&content[0..20]).expect("deserialize address"),
                );
                Ok(Key::ContractMeta(address))
            }
            KeyType::LockLiveCell => {
                let lock_hash = H256::from_slice(&content[0..32]).expect("deserialize address");
                let number = deserialize_u64(&content[32..40]);
                let tx_index = deserialize_u32(&content[40..44]);
                let output_index = deserialize_u32(&content[44..48]);
                Ok(Key::LockLiveCell {
                    lock_hash,
                    number: Some(number),
                    tx_index: Some(tx_index),
                    output_index: Some(output_index),
                })
            }
            KeyType::LiveCellMap => {
                let out_point = packed::OutPoint::from_slice(content).unwrap();
                Ok(Key::LiveCellMap(out_point))
            }
            KeyType::BlockDelta => {
                ensure_content_len("BlockDelta", content, mem::size_of::<BlockNumber>())?;
                let number = deserialize_u64(&content[0..8]);
                Ok(Key::BlockDelta(number))
            }
        }
    }
}

pub mod value {
    use super::BlockNumber;
    use crate::types::{ContractAddress, EoaAddress};
    use ckb_types::{bytes::Bytes, packed, prelude::*, H256};
    use serde::{Deserialize, Serialize};

    /// Deserialize/Serialize use bincode
    #[derive(Debug, Clone, Deserialize, Serialize)]
    pub struct Last {
        pub number: BlockNumber,
        pub hash: H256,
    }

    #[derive(Debug, Clone, Deserialize, Serialize)]
    pub struct BlockMap(pub H256);

    #[derive(Debug, Clone, Deserialize, Serialize)]
    pub struct ContractChange {
        pub tx_hash: H256,
        pub tx_origin: EoaAddress,
        pub new_storage: Vec<(H256, H256)>,
        pub capacity: u64,
        pub balance: u64,
        pub is_create: bool,
    }

    #[derive(Debug, Clone, Deserialize, Serialize)]
    pub struct ContractMeta {
        pub code: Bytes,
        /// The hash of the transaction where the contract created
        pub tx_hash: H256,
        /// The output index of the transaction where the contract created
        pub output_index: u32,
        /// The balance of the contract
        pub balance: u128,
        /// Check if the contract is destructed
        pub destructed: bool,
    }

    #[derive(Debug, Clone, Deserialize, Serialize)]
    pub struct ContractLogs(pub Vec<(Vec<H256>, Bytes)>);

    #[derive(Debug, Clone, Deserialize, Serialize, Hash, Eq, PartialEq)]
    pub struct LockLiveCell {
        pub tx_hash: H256,
        pub output_index: u32,
        pub capacity: u64,
        pub type_script_hash: Option<H256>,
        pub data_size: u32,
    }

    impl LockLiveCell {
        pub fn out_point(&self) -> packed::OutPoint {
            packed::OutPoint::new(self.tx_hash.pack(), self.output_index)
        }
    }

    #[derive(Debug, Clone, Deserialize, Serialize)]
    pub struct LiveCellMap {
        pub number: BlockNumber,
        pub tx_index: u32,
    }

    /// For rollback
    #[derive(Debug, Clone, Deserialize, Serialize)]
    pub struct BlockDelta {
        /// If the bool field is true, the contract is created in this block
        pub contracts: Vec<(ContractAddress, bool)>,
        /// (lock_hash, tx_index, output_index)
        pub added_cells: Vec<(H256, u32, u32, LockLiveCell)>,
        /// (lock_hash, number, tx_index, output_index)
        pub removed_cells: Vec<(H256, u64, u32, u32, LockLiveCell)>,
        /// The selfdestruct contracts in current block
        pub destructed_contracts: Vec<ContractAddress>,
    }
}

fn db_get<K: AsRef<[u8]>, T: DeserializeOwned>(db: &DB, key: K) -> Result<Option<T>, String> {
    db.get(key)
        .map_err(|err| err.to_string())?
        .map(|value_bytes| deserialize(&value_bytes).map_err(|err| err.to_string()))
        .transpose()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_key_serde() {
        for key1 in vec![
            Key::Last,
            Key::BlockMap(3),
            Key::ContractChange {
                address: Default::default(),
                number: Some(333),
                tx_index: Some(2),
                output_index: Some(64),
            },
            Key::ContractLogs {
                address: Default::default(),
                number: Some(444),
                tx_index: Some(3),
                output_index: Some(64),
            },
            Key::ContractMeta(Default::default()),
            Key::LockLiveCell {
                lock_hash: Default::default(),
                number: Some(666),
                tx_index: Some(4),
                output_index: Some(55),
            },
            Key::LiveCellMap(packed::OutPoint::default()),
            Key::BlockDelta(8),
        ] {
            let binary = Bytes::from(&key1);
            let key2 = Key::try_from(binary.as_ref()).unwrap();
            assert_eq!(key1, key2);
        }
    }
}
