use ckb_hash::blake2b_256;
use ckb_simple_account_layer::RunProofResult;
use ckb_types::{
    bytes::{BufMut, Bytes, BytesMut},
    H160, H256, U256,
};
use secp256k1::recovery::{RecoverableSignature, RecoveryId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::TryFrom;

use crate::storage::{value, Key};

lazy_static::lazy_static! {
    pub static ref SECP256K1: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}

/// A contract account's cell data
pub struct ContractCell {
    /// The merkle root of key-value storage
    pub storage_root: H256,
    /// The transaction code hash (code_hash = blake2b(code), to verify the code in witness)
    pub code_hash: H256,
}

/// The witness data will be serialized and put into CKB transaction.
/// NOTE:
///   - Cannot put this witness in lock field
///   - May not work with Nervos DAO
#[derive(Clone)]
pub struct WitnessData {
    /// The signature of CKB transaction.
    ///
    ///     data_1 = tx_hash
    ///     data_2 = init_witness([0u8; 65] ++ program ++ run_proof)
    ///     signature = sign_recoverable(data_1 ++ data_2)
    ///
    pub signature: [u8; 65],
    /// The ethereum transaction(program) to run.
    pub program: Program,
    /// Provide storage diff and diff proofs.
    pub run_proof: RunProofResult,
}

/// Represent an ethereum transaction
#[derive(Clone)]
pub struct Program {
    /// If CREATE contract the input data is constructor and it's parameters (and code is None)
    /// If  CALL  contract the input data is the parameters for target function (and code is not None)
    pub input: Bytes,
    /// The code to run the contract, when create a contract, the code is None
    pub code: Option<Bytes>,
}

/// The contract code
pub struct ContractCode {
    pub address: ContractAddress,
    pub code: Bytes,
    /// The hash of the transaction where the contract created
    pub tx_hash: H256,
    /// The output index of the transaction where the contract created
    pub output_index: u32,
}

/// Represent a change record of a contract call
#[derive(Default)]
pub struct ContractChange {
    pub sender: EoaAddress,
    pub address: ContractAddress,
    /// Block number
    pub number: u64,
    /// Transaction index in current block
    pub tx_index: u32,
    /// Output index in current transaction
    pub output_index: u32,
    pub tx_hash: H256,
    pub new_storage: HashMap<H256, H256>,
    pub logs: Vec<(Vec<H256>, Bytes)>,
    /// The change is create the contract
    pub is_create: bool,
}

/// The EOA account address.
/// Just the secp256k1_blake160 lock args, can be calculated from signature.
///
///     address = blake2b(pubkey)[0..20]
///
#[derive(Default, Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct EoaAddress(pub H160);

/// The contract account address.
/// Use `type_id` logic to ensure it's uniqueness.
/// Please see: https://github.com/nervosnetwork/ckb/blob/v0.31.1/script/src/type_id.rs
///
///     data_1  = first_input.as_slice();
///     data_2  = first_output_index_in_current_group.to_le_bytes()
///     address = blake2b(data_1 ++ data_2)[12..]
///
#[derive(Default, Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContractAddress(pub H160);

/// The log produced by LOG0,LOG1,LOG2,LOG3,LOG4
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub address: ContractAddress,
    pub topics: Vec<H256>,
    pub data: Bytes,
}

/// The transaction receipt, removed fields:
///   - cumulative_gas_used
///   - gas_used
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionReceipt {
    pub transaction_hash: H256,
    pub transaction_index: U256,
    pub block_hash: H256,
    pub block_number: U256,
    pub from: EoaAddress,
    pub to: Option<ContractAddress>,
    pub contract_address: Option<ContractAddress>,
    pub logs: Vec<LogEntry>,
    pub logs_bloom: H256,
    pub status: U256,
}

impl From<ContractAddress> for H160 {
    fn from(addr: ContractAddress) -> H160 {
        addr.0
    }
}
impl From<H160> for ContractAddress {
    fn from(inner: H160) -> ContractAddress {
        ContractAddress(inner)
    }
}
impl TryFrom<&[u8]> for ContractAddress {
    type Error = String;
    fn try_from(source: &[u8]) -> Result<ContractAddress, String> {
        H160::from_slice(source)
            .map(ContractAddress)
            .map_err(|err| err.to_string())
    }
}
impl From<EoaAddress> for H160 {
    fn from(addr: EoaAddress) -> H160 {
        addr.0
    }
}
impl From<H160> for EoaAddress {
    fn from(inner: H160) -> EoaAddress {
        EoaAddress(inner)
    }
}

impl TryFrom<&[u8]> for WitnessData {
    type Error = String;
    fn try_from(data: &[u8]) -> Result<WitnessData, String> {
        Err(String::from("TODO: WitnessData::try_from"))
    }
}

impl WitnessData {
    pub fn program_data(&self) -> Bytes {
        let mut buf = BytesMut::from(&self.signature[..]);
        buf.put(&self.program.input.len().to_le_bytes()[..]);
        buf.put(self.program.input.as_ref());
        let code = self.program.code.clone().unwrap_or_default();
        buf.put(&code.len().to_le_bytes()[..]);
        buf.put(code.as_ref());
        buf.freeze()
    }

    pub fn unsigned_data(&self, tx_hash: &H256) -> Result<Bytes, String> {
        let mut program_data = self.program_data();
        let mut data = BytesMut::from(tx_hash.as_bytes());
        data.put(&[0u8; 32][..]);
        data.put(&program_data.as_ref()[32..]);
        self.run_proof
            .serialize(&data.freeze())
            .map_err(|err| err.to_string())
    }

    pub fn recover_pubkey(&self, tx_hash: &H256) -> Result<secp256k1::PublicKey, String> {
        let unsigned_data = self.unsigned_data(tx_hash)?;
        let message = secp256k1::Message::from_slice(&blake2b_256(&unsigned_data)[..])
            .map_err(|err| err.to_string())?;

        let mut signature_data = [0u8; 64];
        signature_data.copy_from_slice(&self.signature[0..64]);
        let recov_id =
            RecoveryId::from_i32(self.signature[64] as i32).map_err(|err| err.to_string())?;
        let signature = RecoverableSignature::from_compact(&signature_data[..], recov_id)
            .map_err(|err| err.to_string())?;
        SECP256K1
            .recover(&message, &signature)
            .map_err(|err| err.to_string())
    }

    pub fn recover_sender(&self, tx_hash: &H256) -> Result<EoaAddress, String> {
        let pubkey = self.recover_pubkey(tx_hash)?;
        let hash = H160::from_slice(&blake2b_256(&pubkey.serialize()[..])[0..20])
            .expect("Generate hash(H160) from pubkey failed");
        Ok(EoaAddress(hash))
    }
}

impl ContractCode {
    pub fn db_key(&self) -> Key {
        Key::ContractCode(self.address.clone())
    }
    pub fn db_value(&self) -> value::ContractCode {
        value::ContractCode {
            code: self.code.clone(),
            tx_hash: self.tx_hash.clone(),
            output_index: self.output_index,
        }
    }
}

impl ContractChange {
    pub fn db_key(&self) -> Key {
        Key::ContractChange {
            address: self.address.clone(),
            number: Some(self.number),
            tx_index: Some(self.tx_index),
            output_index: Some(self.output_index),
        }
    }
    pub fn db_value(&self) -> value::ContractChange {
        value::ContractChange {
            tx_hash: self.tx_hash.clone(),
            sender: self.sender.clone(),
            new_storage: self.new_storage.clone().into_iter().collect(),
            is_create: self.is_create,
        }
    }
    pub fn db_key_logs(&self) -> Option<Key> {
        if self.logs.is_empty() {
            None
        } else {
            Some(Key::ContractLogs {
                address: self.address.clone(),
                number: Some(self.number),
                tx_index: Some(self.tx_index),
                output_index: Some(self.output_index),
            })
        }
    }
    pub fn db_value_logs(&self) -> value::ContractLogs {
        value::ContractLogs(self.logs.clone())
    }
}
