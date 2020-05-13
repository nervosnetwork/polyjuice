

use bytes::Bytes;
use ethereum_types::{H256, U256, H160};

/// A contract account's main cell
pub struct ContractCell {
    /// The merkle root of key-value storage
    storage_root: H256,
    /// The transaction code hash (keccak256)
    code_hash: H256,
}

/// The witness data will be serialized and put into CKB transaction
pub struct WitnessData {
    /// The ethereum transaction.
    ///   - For verify the `signature` and `sender` address
    ///   - For get the `input-data` to run the contract
    tx: eth::Transaction,
    /// The code to run the contract, when create a contract, the code is None
    code: Option<Bytes>,
    /// Provide storage diff and diff proofs
    run_proof: RunProofResult,
}

// FIXME: ref to `ckb-simple-account-layer`
pub struct RunProofResult {
    /// Pairs of values in the old tree that is read by the program
    pub read_values: Vec<(H256, H256)>,
    /// Proof of read_values
    pub read_proof: Bytes,
    /// Tuple of values that is written by the program. Order of items is
    /// key, old value, new value
    pub write_values: Vec<(H256, H256, H256)>,
    /// Proof of all old values in write_values in the old tree. This proof
    /// Can also be used together with new values in write_values to calculate
    /// new root hash
    pub write_old_proof: Bytes,
}

pub mod eth {
    // A customized ETH transaction (Custome the way to sign the transaction)
    pub struct Transaction {}
    pub struct Address {}
}
