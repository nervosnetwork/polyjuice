use ckb_hash::blake2b_256;
use ckb_jsonrpc_types as json_types;
use ckb_simple_account_layer::{CkbBlake2bHasher, Config, RunResult};
use ckb_types::{
    bytes::{BufMut, Bytes, BytesMut},
    core::{DepType, EpochNumberWithFraction, ScriptHashType},
    h256, packed,
    prelude::*,
    H160, H256,
};
use secp256k1::recovery::{RecoverableSignature, RecoveryId};
use serde::{Deserialize, Serialize};
use sparse_merkle_tree::{default_store::DefaultStore, SparseMerkleTree, H256 as SmtH256};
use std::collections::HashMap;
use std::convert::TryFrom;

use crate::storage::{value, Key};

pub const ONE_CKB: u64 = 100_000_000;
pub const MIN_CELL_CAPACITY: u64 = 61 * ONE_CKB;

pub const SIGHASH_TYPE_HASH: H256 =
    h256!("0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8");
pub const ALWAYS_SUCCESS_CODE_HASH: H256 =
    h256!("0x28e83a1277d48add8e72fadaa9248559e1b632bab2bd60b27955ebc4c03800a5");

pub const CELLBASE_MATURITY: EpochNumberWithFraction =
    EpochNumberWithFraction::new_unchecked(4, 0, 1);

lazy_static::lazy_static! {
    pub static ref SECP256K1: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
    pub static ref SIGHASH_CELL_DEP: packed::CellDep = {
        let out_point = packed::OutPoint::new_builder()
            .tx_hash(h256!("0xace5ea83c478bb866edf122ff862085789158f5cbff155b7bb5f13058555b708").pack())
            .index(0u32.pack())
            .build();
        packed::CellDep::new_builder()
            .out_point(out_point)
            .dep_type(DepType::DepGroup.into())
            .build()
    };
    pub static ref ALWAYS_SUCCESS_OUT_POINT: packed::OutPoint = {
        // FIXME: replace this later
        packed::OutPoint::new_builder()
            .tx_hash(h256!("0x1111111111111111111111111111111111111111111111111111111111111111").pack())
            .index(0u32.pack())
            .build()
    };
    pub static ref ALWAYS_SUCCESS_CELL_DEP: packed::CellDep = {
        packed::CellDep::new_builder()
            .out_point(ALWAYS_SUCCESS_OUT_POINT.clone())
            .dep_type(DepType::Code.into())
            .build()
    };
    pub static ref ALWAYS_SUCCESS_SCRIPT: packed::Script = {
        packed::Script::new_builder()
            .code_hash(ALWAYS_SUCCESS_CODE_HASH.pack())
            .hash_type(ScriptHashType::Data.into())
            .build()
    };
}

#[derive(Debug, Clone)]
pub struct RunConfig {
    pub generator: Bytes,
    // Type script (validator)
    pub type_dep: packed::CellDep,
    pub type_script: packed::Script,
    // Lock script
    pub lock_dep: packed::CellDep,
    pub lock_script: packed::Script,
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessData {
    /// The signature of CKB transaction.
    ///     data_1 = [0u8; 65]
    ///     data_2 = program.len() ++ program
    ///     data_3 = return_data.len() ++ return_data
    ///     program_data = data_1 ++ data_2 ++ data_3
    ///
    ///     data_1 = tx_hash
    ///     data_2 = program_data.len() ++ program_data
    ///     data_3 = run_proof
    ///     signature = sign_recoverable(data_1 ++ data_2 ++ data_3)
    ///
    pub signature: Bytes,
    /// The ethereum program(transaction) to run.
    pub program: Program,
    /// The return data
    pub return_data: Bytes,
    /// The call's selfdestruct target
    pub selfdestruct: Option<H160>,
    /// Provide storage diff and diff proofs.
    pub run_proof: Bytes,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
#[serde(rename_all = "lowercase")]
#[repr(u8)]
pub enum CallKind {
    // < Request CALL.
    CALL = 0,
    // < Request DELEGATECALL. Valid since Homestead. The value param ignored.
    DELEGATECALL = 1,
    // < Request CALLCODE.
    CALLCODE = 2,
    // < Request CREATE.
    CREATE = 3,
    // < Request CREATE2. Valid since Constantinople.
    CREATE2 = 4,
}

/// Represent an ethereum transaction
// TODO: pub value: U256
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Program {
    /// The kind of the call. For zero-depth calls ::EVMC_CALL SHOULD be used.
    pub kind: CallKind,
    /// Additional flags modifying the call execution behavior.
    /// In the current version the only valid values are ::EVMC_STATIC or 0.
    pub flags: u32,
    /// The call depth.
    pub depth: u32,

    /// The sender of the message. (MUST be verified by the signature in witness data)
    pub sender: EoaAddress,
    /// The destination of the message (MUST be verified by the script args).
    pub destination: ContractAddress,
    /// The code to create/call the contract
    pub code: Bytes,
    /// The input data to create/call the contract
    pub input: Bytes,
}

/// The contract metadata
pub struct ContractMeta {
    pub address: ContractAddress,
    pub code: Bytes,
    /// The hash of the transaction where the contract created
    pub tx_hash: H256,
    /// The output index of the transaction where the contract created
    pub output_index: u32,
    pub destructed: bool,
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
///     address = blake2b(data_1 ++ data_2)[0..20]
///
#[derive(Default, Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContractAddress(pub H160);

// TODO: Move this struct to server.rs
/// The transaction receipt
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionReceipt {
    pub tx: json_types::Transaction,
    /// The newly created contract's address (Program.depth=0)
    pub contract_address: Option<ContractAddress>,
    pub return_data: Option<json_types::JsonBytes>,
    pub logs: Vec<(Vec<H256>, json_types::JsonBytes)>,
}

impl From<&RunConfig> for Config {
    fn from(cfg: &RunConfig) -> Config {
        let mut config = Config::default();
        config.generator = cfg.generator.clone();
        config.validator_outpoint = cfg.type_dep.out_point();
        config.type_script = cfg.type_script.clone();
        config
    }
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

impl Default for CallKind {
    fn default() -> CallKind {
        CallKind::CALL
    }
}

impl TryFrom<&[u8]> for WitnessData {
    type Error = String;
    fn try_from(data: &[u8]) -> Result<WitnessData, String> {
        let mut offset = 0;
        let (signature, program, return_data, selfdestruct) = {
            let program_data = load_var_slice(data, &mut offset)?;
            log::trace!("program_data: {}", hex::encode(&program_data));
            let mut inner_offset = 0;
            let mut signature = [0u8; 65];
            let tmp = load_slice_with_length(program_data, 65, &mut inner_offset)?;
            signature.copy_from_slice(tmp.as_ref());
            let program_slice = load_var_slice(program_data, &mut inner_offset)?;
            log::trace!("program: {}", hex::encode(&program_slice));
            let program = Program::try_from(program_slice)?;
            let return_data = load_var_slice(program_data, &mut inner_offset)?;
            let selfdestruct_target = load_h160(program_data, &mut inner_offset)?;
            let selfdestruct = if selfdestruct_target == H160::default() {
                None
            } else {
                Some(selfdestruct_target)
            };
            (
                Bytes::from(signature[..].to_vec()),
                program,
                Bytes::from(return_data.to_vec()),
                selfdestruct,
            )
        };
        let run_proof = Bytes::from(data[offset..].to_vec());
        Ok(WitnessData {
            signature,
            program,
            return_data,
            selfdestruct,
            run_proof,
        })
    }
}

impl Program {
    pub fn new_create(sender: EoaAddress, code: Bytes) -> Program {
        Program {
            kind: CallKind::CREATE,
            flags: 0,
            depth: 0,
            sender,
            destination: ContractAddress::default(),
            code,
            input: Bytes::default(),
        }
    }

    pub fn new_call(
        sender: EoaAddress,
        destination: ContractAddress,
        code: Bytes,
        input: Bytes,
        is_static: bool,
    ) -> Program {
        let flags = if is_static { 1 } else { 0 };
        Program {
            kind: CallKind::CALL,
            flags,
            depth: 0,
            sender,
            destination,
            code,
            input,
        }
    }

    pub fn serialize(&self) -> Bytes {
        let mut buf = BytesMut::default();
        buf.put(&[self.kind as u8][..]);
        buf.put(&self.flags.to_le_bytes()[..]);
        buf.put(&self.depth.to_le_bytes()[..]);
        buf.put(self.sender.0.as_bytes());
        buf.put(self.destination.0.as_bytes());

        buf.put(&(self.code.len() as u32).to_le_bytes()[..]);
        buf.put(self.code.as_ref());
        buf.put(&(self.input.len() as u32).to_le_bytes()[..]);
        buf.put(self.input.as_ref());
        buf.freeze()
    }
}

impl TryFrom<&[u8]> for Program {
    type Error = String;
    fn try_from(data: &[u8]) -> Result<Program, String> {
        // Make sure access data[0] not panic
        if data.is_empty() {
            return Err(format!(
                "Not enough data length for parse Program: {}",
                data.len()
            ));
        }

        let kind = CallKind::try_from(data[0])?;
        let mut offset: usize = 1;
        let flags = load_u32(data, &mut offset)?;
        let depth = load_u32(data, &mut offset)?;
        let sender = EoaAddress(load_h160(data, &mut offset)?);
        let destination = ContractAddress(load_h160(data, &mut offset)?);
        let code = load_var_slice(data, &mut offset)?;
        let input = load_var_slice(data, &mut offset)?;
        if !data[offset..].is_empty() {
            return Err(format!("To much data for parse Program: {}", data.len()));
        }
        Ok(Program {
            kind,
            flags,
            depth,
            sender,
            destination,
            code: Bytes::from(code.to_vec()),
            input: Bytes::from(input.to_vec()),
        })
    }
}

impl TryFrom<u8> for CallKind {
    type Error = String;
    fn try_from(value: u8) -> Result<CallKind, String> {
        match value {
            0 => Ok(CallKind::CALL),
            1 => Ok(CallKind::DELEGATECALL),
            2 => Ok(CallKind::CALLCODE),
            3 => Ok(CallKind::CREATE),
            4 => Ok(CallKind::CREATE2),
            _ => Err(format!("Invalid call kind: {}", value)),
        }
    }
}

impl WitnessData {
    pub fn new(program: Program) -> WitnessData {
        WitnessData {
            signature: Bytes::from(vec![0u8; 65]),
            program,
            return_data: Bytes::default(),
            selfdestruct: None,
            run_proof: Bytes::default(),
        }
    }

    pub fn update_result(&mut self, result: &RunResult) -> Result<(), String> {
        self.return_data = result.return_data.clone();
        self.selfdestruct = result
            .selfdestruct
            .clone()
            .map(|target| H160::from_slice(target.as_ref()).map_err(|err| err.to_string()))
            .transpose()?;
        Ok(())
    }

    pub fn serialize(&self) -> Bytes {
        let mut buf = BytesMut::default();
        let program_data = self.program_data();
        buf.put(&(program_data.len() as u32).to_le_bytes()[..]);
        buf.put(program_data.as_ref());
        buf.put(self.run_proof.as_ref());
        buf.freeze()
    }

    pub fn program_data(&self) -> Bytes {
        let mut buf = BytesMut::from(&self.signature[..]);
        let program = self.program.serialize();
        log::trace!("program: {}", hex::encode(program.as_ref()));
        buf.put(&(program.len() as u32).to_le_bytes()[..]);
        buf.put(program.as_ref());
        buf.put(&(self.return_data.len() as u32).to_le_bytes()[..]);
        buf.put(self.return_data.as_ref());
        buf.put(self.selfdestruct.clone().unwrap_or_default().as_bytes());
        buf.freeze()
    }

    /// unsigned_data = tx_hash ++ program.len() ++ program ++ run_proof
    pub fn unsigned_data(&self, tx_hash: &H256) -> Bytes {
        let mut program_data = self.program_data();
        let mut data = BytesMut::from(tx_hash.as_bytes());
        data.put(&(program_data.len() as u32).to_le_bytes()[..]);
        data.put(&[0u8; 32][..]);
        data.put(&program_data.as_ref()[32..]);
        data.put(self.run_proof.as_ref());
        data.freeze()
    }

    pub fn secp_message(&self, tx_hash: &H256) -> Result<secp256k1::Message, String> {
        let unsigned_data = self.unsigned_data(tx_hash);
        secp256k1::Message::from_slice(&blake2b_256(&unsigned_data)[..])
            .map_err(|err| err.to_string())
    }

    pub fn recover_pubkey(&self, tx_hash: &H256) -> Result<secp256k1::PublicKey, String> {
        let message = self.secp_message(tx_hash)?;
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

impl ContractMeta {
    pub fn db_key(&self) -> Key {
        Key::ContractMeta(self.address.clone())
    }
    pub fn db_value(&self) -> value::ContractMeta {
        value::ContractMeta {
            code: self.code.clone(),
            tx_hash: self.tx_hash.clone(),
            output_index: self.output_index,
            destructed: self.destructed,
        }
    }
}

impl ContractChange {
    pub fn merkle_tree(
        &self,
    ) -> SparseMerkleTree<CkbBlake2bHasher, SmtH256, DefaultStore<SmtH256>> {
        let mut tree = SparseMerkleTree::default();
        for (key, value) in &self.new_storage {
            tree.update(h256_to_smth256(key), h256_to_smth256(value))
                .unwrap();
        }
        tree
    }

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

pub fn smth256_to_h256(hash: &SmtH256) -> H256 {
    H256::from_slice(hash.as_slice()).unwrap()
}

pub fn h256_to_smth256(hash: &H256) -> SmtH256 {
    let mut buf = [0u8; 32];
    buf.copy_from_slice(hash.as_bytes());
    SmtH256::from(buf)
}

pub fn load_u32(data: &[u8], offset: &mut usize) -> Result<u32, String> {
    let offset_value = *offset;
    if data[offset_value..].len() < 4 {
        return Err(format!(
            "Not enough data length to parse u32: data.len={}, offset={}",
            data.len(),
            offset
        ));
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&data[offset_value..offset_value + 4]);
    let value = u32::from_le_bytes(buf);
    log::trace!(
        "[load] u32  : offset={:>3}, value ={:>3}, slice={}",
        offset,
        value,
        hex::encode(&buf[..])
    );
    *offset += 4;
    Ok(value)
}

pub fn load_fixed_hash<T: std::fmt::LowerHex, F: Fn(&[u8]) -> T>(
    type_name: &str,
    data: &[u8],
    offset: &mut usize,
    converter: F,
) -> Result<T, String> {
    let hash_size: usize = std::mem::size_of::<T>();
    let offset_value = *offset;
    if data[offset_value..].len() < hash_size {
        return Err(format!(
            "Not enough data length to parse {}: data.len={}, offset={}",
            type_name,
            data.len(),
            offset_value
        ));
    }
    let inner = converter(&data[offset_value..offset_value + hash_size]);
    log::trace!(
        "[load] {} : offset={:>3}, value={:x}",
        type_name,
        offset,
        inner
    );
    *offset += hash_size;
    Ok(inner)
}

pub fn load_h160(data: &[u8], offset: &mut usize) -> Result<H160, String> {
    load_fixed_hash("H160", data, offset, |slice| {
        H160::from_slice(slice).unwrap()
    })
}
pub fn load_h256(data: &[u8], offset: &mut usize) -> Result<H256, String> {
    load_fixed_hash("H256", data, offset, |slice| {
        H256::from_slice(slice).unwrap()
    })
}

pub fn load_slice_with_length<'a>(
    data: &'a [u8],
    length: u32,
    offset: &mut usize,
) -> Result<&'a [u8], String> {
    let offset_value = *offset;
    let length = length as usize;
    if data[offset_value..].len() < length {
        return Err(format!(
            "Not enough data length to parse Bytes: data.len={}, length={}, offset={}",
            data.len(),
            length,
            offset_value
        ));
    }
    let target = &data[offset_value..offset_value + length];
    log::trace!(
        "[load] slice: offset={:>3}, length={:>3}, slice={}",
        offset,
        length,
        hex::encode(target)
    );
    *offset += length;
    Ok(target)
}

pub fn load_var_slice<'a>(data: &'a [u8], offset: &mut usize) -> Result<&'a [u8], String> {
    let length = load_u32(data, offset)?;
    load_slice_with_length(data, length, offset)
}

pub fn parse_log(raw: &[u8]) -> Result<(Vec<H256>, Bytes), String> {
    let mut offset = 0;
    let data_slice = load_var_slice(raw, &mut offset)?;
    let mut topics = Vec::new();
    let topics_count = load_u32(raw, &mut offset)?;
    for _ in 0..topics_count {
        topics.push(load_h256(raw, &mut offset)?);
    }
    Ok((topics, Bytes::from(data_slice.to_vec())))
}

#[cfg(test)]
mod test {
    use super::*;
    use ckb_simple_account_layer::RunProofResult;

    #[test]
    fn test_serde_program() {
        let program1 = Program::new_create(Default::default(), Bytes::from("abcdef"));
        let binary = program1.serialize();
        let program2 = Program::try_from(binary.as_ref()).unwrap();
        assert_eq!(program1, program2);
    }

    #[test]
    fn test_serde_witness_data() {
        let data = hex::decode("95010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000038010000000000000000000000c8328aabcd9b9e8e64fbc566c4385c3bdeb219d7fa36e4fb6bf83b0d4ff5ac34c10e1f56893c9e4edb00000060806040526004361060295760003560e01c806360fe47b114602f5780636d4ce63c14605b576029565b60006000fd5b60596004803603602081101560445760006000fd5b81019080803590602001909291905050506084565b005b34801560675760006000fd5b50606e6094565b6040518082815260200191505060405180910390f35b8060006000508190909055505b50565b6000600060005054905060a2565b9056fea26469706673582212204e58804e375d4a732a7b67cce8d8ffa904fa534d4555e655a433ce0a5e0d339f64736f6c634300060600332400000060fe47b100000000000000000000000000000000000000000000000000000000000000230000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000022010000004c").unwrap();
        WitnessData::try_from(data.as_slice()).unwrap();

        let run_proof = RunProofResult::default();
        let run_proof_data = run_proof.serialize_pure().unwrap();
        let witness_data1 = WitnessData {
            signature: Bytes::from([1u8; 65].to_vec()),
            program: Program::new_create(Default::default(), Bytes::from("abcdef")),
            return_data: Bytes::from("return data"),
            selfdestruct: None,
            run_proof: Bytes::from(run_proof_data),
        };
        let program_data = witness_data1.program_data();
        let binary = run_proof.serialize(&program_data).unwrap();
        let witness_data2 = WitnessData::try_from(binary.as_ref()).unwrap();
        assert_eq!(witness_data1, witness_data2);
    }
}
