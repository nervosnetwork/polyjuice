use ckb_hash::{blake2b_256, new_blake2b};
use ckb_simple_account_layer::{run, CkbBlake2bHasher, Config, RunProofResult, RunResult};
use ckb_types::{
    bytes::{BufMut, Bytes, BytesMut},
    core::{ScriptHashType, TransactionBuilder},
    packed::{
        BytesOpt, CellInput, CellOutput, OutPoint, Script, ScriptOpt, Transaction, WitnessArgs,
    },
    prelude::*,
    H160,
};
use sparse_merkle_tree::{default_store::DefaultStore, SparseMerkleTree, H256 as SmtH256};
use std::error::Error as StdError;

use super::Loader;
use crate::types::{
    ContractAddress, EoaAddress, Program, RunConfig, WitnessData, ALWAYS_SUCCESS_SCRIPT,
    MIN_CELL_CAPACITY, ONE_CKB, SIGHASH_CELL_DEP, SIGHASH_TYPE_HASH,
};

pub struct Runner {
    pub loader: Loader,
    pub run_config: RunConfig,
}

impl Runner {
    pub fn new(loader: Loader, run_config: RunConfig) -> Runner {
        Runner { loader, run_config }
    }

    pub fn static_call(
        &mut self,
        sender: EoaAddress,
        destination: ContractAddress,
        input: Bytes,
    ) -> Result<RunResult, Box<dyn StdError>> {
        log::debug!("loading code ...");
        let meta = self.loader.load_contract_meta(destination.clone())?;
        if meta.destructed {
            return Err(format!("Contract already destructed: {:x}", destination.0).into());
        }
        let code = meta.code;
        let code_hash = blake2b_256(code.as_ref());
        log::debug!("loading change ...");
        let latest_change =
            self.loader
                .load_latest_contract_change(destination.clone(), None, false, false)?;
        let program = Program::new_call(sender, destination, code, input, false);

        let latest_tree = latest_change.merkle_tree();
        let mut witness_data = WitnessData::new(program);
        let program_data = witness_data.program_data();

        let config: Config = (&self.run_config).into();
        log::debug!(
            "[length]: {}",
            hex::encode(&(program_data.len() as u32).to_le_bytes()[..])
        );
        log::debug!("[binary]: {}", hex::encode(program_data.as_ref()));
        let result = match run(&config, &latest_tree, &program_data) {
            Ok(result) => {
                let new_root_hash = result.committed_root_hash(&latest_tree)?;
                if &new_root_hash != latest_tree.root() {
                    return Err(String::from("Storage changed in static call").into());
                }
                result
            }
            Err(err) => {
                log::warn!("Error: {:?}", err);
                return Err(err);
            }
        };
        Ok(result)
    }

    pub fn call(
        &mut self,
        sender: EoaAddress,
        destination: ContractAddress,
        input: Bytes,
    ) -> Result<(Transaction, RunResult), Box<dyn StdError>> {
        let meta = self.loader.load_contract_meta(destination.clone())?;
        if meta.destructed {
            return Err(format!("Contract already destructed: {:x}", destination.0).into());
        }
        let code = meta.code;
        let code_hash = blake2b_256(code.as_ref());
        let latest_change =
            self.loader
                .load_latest_contract_change(destination.clone(), None, false, false)?;
        let (contract_live_cell, latest_contract_data) = self
            .loader
            .load_contract_live_cell(latest_change.tx_hash.clone(), latest_change.output_index)?;
        let latest_root_hash = &latest_contract_data.as_ref()[0..32];
        let latest_code_hash = &latest_contract_data.as_ref()[32..];
        assert_eq!(&code_hash[..], latest_code_hash, "code hash not match");
        let program = Program::new_call(sender, destination, code, input, false);

        let tx_fee = ONE_CKB;
        let (mut live_cells, total_capacity) = self
            .loader
            .collect_cells(program.sender.clone(), tx_fee + MIN_CELL_CAPACITY)?;
        let out_point = OutPoint::new(latest_change.tx_hash.pack(), latest_change.output_index);
        // Should add to the head of inputs
        live_cells.insert(0, out_point);

        let latest_tree = latest_change.merkle_tree();
        let mut witness_data = WitnessData::new(program.clone());
        let program_data = witness_data.program_data();

        log::debug!(
            "[length]: {}",
            hex::encode(&(program_data.len() as u32).to_le_bytes()[..])
        );
        log::debug!("[binary]: {}", hex::encode(program_data.as_ref()));
        let config: Config = (&self.run_config).into();
        let result = match run(&config, &latest_tree, &program_data) {
            Ok(result) => result,
            Err(err) => {
                log::warn!("Error: {:?}", err);
                return Err(err);
            }
        };
        let proof = result.generate_proof(&latest_tree)?;
        print_proof(&proof);
        let root_hash = result.committed_root_hash(&latest_tree)?;
        if result.selfdestruct.is_none() && root_hash.as_slice() == latest_root_hash {
            // TODO handle value change
            return Err(String::from("Storage unchanged!").into());
        }

        // 1. cell deps
        // 2. inputs
        let inputs = live_cells
            .into_iter()
            .map(|out_point| CellInput::new(out_point, 0))
            .collect::<Vec<_>>();
        // 3. outputs
        let (output, output_data) = if let Some(ref selfdestruct_target) = result.selfdestruct {
            let output = CellOutput::new_builder()
                .lock(
                    Script::new_builder()
                        .code_hash(SIGHASH_TYPE_HASH.pack())
                        .hash_type(ScriptHashType::Type.into())
                        .args(selfdestruct_target.pack())
                        .build(),
                )
                .capacity(contract_live_cell.capacity())
                .build();
            (output, Bytes::default())
        } else {
            let mut output_data = BytesMut::from(root_hash.as_slice());
            output_data.put(&code_hash[..]);
            (contract_live_cell, output_data.freeze())
        };
        // 4. witness
        witness_data.update_result(&result)?;
        let program_data = witness_data.program_data();
        let s = proof.serialize(&program_data)?;
        log::debug!("WitnessData: {}", hex::encode(s.as_ref()));
        let data = BytesOpt::new_builder().set(Some(s.pack())).build();
        let witness = WitnessArgs::new_builder().input_type(data).build();

        let mut transaction_builder = TransactionBuilder::default()
            .cell_dep(SIGHASH_CELL_DEP.clone())
            .cell_dep(self.run_config.type_dep.clone())
            .cell_dep(self.run_config.lock_dep.clone())
            .inputs(inputs.pack())
            .witness(witness.as_bytes().pack())
            .output(output)
            .output_data(output_data.pack());

        let capacity_left = total_capacity - tx_fee;
        if capacity_left >= MIN_CELL_CAPACITY {
            let sender_args = Bytes::from(program.sender.0.as_bytes().to_vec());
            let output = CellOutput::new_builder()
                .lock(
                    Script::new_builder()
                        .code_hash(SIGHASH_TYPE_HASH.pack())
                        .hash_type(ScriptHashType::Type.into())
                        .args(sender_args.pack())
                        .build(),
                )
                .capacity(capacity_left.pack())
                .build();
            transaction_builder = transaction_builder
                .output(output)
                .output_data(Bytes::default().pack());
        }

        let tx = transaction_builder.build();
        Ok((tx.data(), result))
    }

    pub fn create(
        &mut self,
        sender: EoaAddress,
        code: Bytes,
    ) -> Result<(ContractAddress, Transaction, RunResult), Box<dyn StdError>> {
        let program = Program::new_create(sender, code);

        // TODO: let user choose the lock
        let contract_lock_script = ALWAYS_SUCCESS_SCRIPT.clone();

        let tx_fee = ONE_CKB;
        let output_capacity = 200 * ONE_CKB;
        let (live_cells, total_capacity) = self
            .loader
            .collect_cells(program.sender.clone(), tx_fee + output_capacity)?;
        let latest_tree: SparseMerkleTree<CkbBlake2bHasher, SmtH256, DefaultStore<SmtH256>> =
            Default::default();
        let mut witness_data = WitnessData::new(program.clone());
        let program_data = witness_data.program_data();

        log::debug!(
            "[length]: {}",
            hex::encode(&(program_data.len() as u32).to_le_bytes()[..])
        );
        log::debug!("[binary]: {}", hex::encode(program_data.as_ref()));
        let config: Config = (&self.run_config).into();
        let result = match run(&config, &latest_tree, &program_data) {
            Ok(result) => result,
            Err(err) => {
                log::warn!("Error: {:?}", err);
                return Err(err);
            }
        };
        let proof = result.generate_proof(&latest_tree)?;
        print_proof(&proof);
        let root_hash = result.committed_root_hash(&latest_tree)?;

        let inputs = live_cells
            .into_iter()
            .map(|out_point| CellInput::new(out_point, 0))
            .collect::<Vec<_>>();
        let type_id_args = {
            let first_cell_input = &inputs[0];
            let first_output_index = 0u64;
            let mut blake2b = new_blake2b();
            blake2b.update(first_cell_input.as_slice());
            blake2b.update(&first_output_index.to_le_bytes());
            let mut ret = [0; 32];
            blake2b.finalize(&mut ret);
            Bytes::from(ret[0..20].to_vec())
        };
        let contract_address = H160::from_slice(type_id_args.as_ref())
            .map(ContractAddress)
            .unwrap();
        let contract_type_script = self
            .run_config
            .type_script
            .clone()
            .as_builder()
            .args(type_id_args.pack())
            .build();

        witness_data.return_data = result.return_data.clone();
        let program_data = witness_data.program_data();
        let s = proof.serialize(&program_data)?;
        log::debug!("WitnessData: {}", hex::encode(s.as_ref()));
        let data = BytesOpt::new_builder().set(Some(s.pack())).build();
        let witness = WitnessArgs::new_builder().output_type(data).build();
        let output = CellOutput::new_builder()
            .type_(
                ScriptOpt::new_builder()
                    .set(Some(contract_type_script))
                    .build(),
            )
            .lock(contract_lock_script)
            .capacity(output_capacity.pack())
            .build();
        let mut output_data = BytesMut::from(root_hash.as_slice());
        output_data.put(&blake2b_256(result.return_data.as_ref())[..]);

        let mut transaction_builder = TransactionBuilder::default()
            .cell_dep(SIGHASH_CELL_DEP.clone())
            .cell_dep(self.run_config.type_dep.clone())
            .cell_dep(self.run_config.lock_dep.clone())
            .inputs(inputs.pack())
            .witness(witness.as_bytes().pack())
            .output(output)
            .output_data(output_data.freeze().pack());

        let capacity_left = total_capacity - tx_fee - output_capacity;
        if capacity_left >= MIN_CELL_CAPACITY {
            let sender_args = Bytes::from(program.sender.0.as_bytes().to_vec());
            let output = CellOutput::new_builder()
                .lock(
                    Script::new_builder()
                        .code_hash(SIGHASH_TYPE_HASH.pack())
                        .hash_type(ScriptHashType::Type.into())
                        .args(sender_args.pack())
                        .build(),
                )
                .capacity(capacity_left.pack())
                .build();
            transaction_builder = transaction_builder
                .output(output)
                .output_data(Bytes::default().pack());
        }
        let tx = transaction_builder.build();
        Ok((contract_address, tx.data(), result))
    }
}

fn print_proof(proof: &RunProofResult) {
    for (i, (key, value)) in proof.read_values.iter().enumerate() {
        log::debug!(
            "read_values[{}]: {} => \n {}",
            i,
            hex::encode(key.as_slice()),
            hex::encode(value.as_slice())
        );
    }
    log::debug!("read_proof: 0x{}", hex::encode(&proof.read_proof[..]));
    for (i, (key, old_value, new_value)) in proof.write_values.iter().enumerate() {
        log::debug!(
            "write_values[{}]: {} => \n (old={}, new={})",
            i,
            hex::encode(key.as_slice()),
            hex::encode(old_value.as_slice()),
            hex::encode(new_value.as_slice())
        );
    }
    log::debug!(
        "write_old_proof: 0x{}",
        hex::encode(&proof.write_old_proof[..])
    );
}
