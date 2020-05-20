use ckb_hash::{blake2b_256, new_blake2b};
use ckb_jsonrpc_types as rpc_types;
use ckb_simple_account_layer::{run, Config};
use ckb_types::{
    bytes::{BufMut, Bytes, BytesMut},
    core::{DepType, ScriptHashType, TransactionBuilder},
    packed::{BytesOpt, CellDep, CellInput, CellOutput, Script, ScriptOpt, WitnessArgs},
    prelude::*,
    H160,
};
use std::error::Error as StdError;

use super::Loader;
use crate::types::{
    CallKind, ContractAddress, Program, TransactionReceipt, ALWAYS_SUCCESS_SCRIPT,
    MIN_CELL_CAPACITY, ONE_CKB, SIGHASH_CELL_DEP, SIGHASH_TYPE_HASH,
};

pub struct Runner {
    pub loader: Loader,
    pub config: Config,
    pub program: Program,
}

impl Runner {
    pub fn new(loader: Loader, config: Config, program: Program) -> Runner {
        Runner {
            loader,
            config,
            program,
        }
    }

    fn program_data(&self) -> Bytes {
        let mut program_data = BytesMut::from(&[0u8; 65][..]);
        program_data.put(self.program.serialize().as_ref());
        program_data.freeze()
    }

    pub fn static_call(&self) -> Result<Bytes, String> {
        let latest_tree = self
            .loader
            .load_latest_contract_change(self.program.destination.clone(), None, false)?
            .merkle_tree();
        let mut program_data = BytesMut::from(&[0u8; 65][..]);
        program_data.put(self.program.serialize().as_ref());
        let result = run(&self.config, &latest_tree, &program_data.freeze())
            .map_err(|err| err.to_string())?;
        Ok(result.return_data)
    }

    pub fn call(&mut self) -> Result<TransactionReceipt, String> {
        if self.program.kind != CallKind::CREATE || self.program.flags != 0 {
            return Err(format!("Expect CALL, found call kind: {:?}", self.program.kind).into());
        }
        Err(format!("TODO: Runner::call"))
    }

    pub fn create(&mut self) -> Result<TransactionReceipt, Box<dyn StdError>> {
        if self.program.kind != CallKind::CREATE {
            return Err(format!("Expect CREATE, found call kind: {:?}", self.program.kind).into());
        }
        // TODO: let user choose the lock
        let contract_lock_script = ALWAYS_SUCCESS_SCRIPT.clone();

        let tx_fee = 1 * ONE_CKB;
        let output_capacity = 200 * ONE_CKB;
        let (live_cells, total_capacity) = self
            .loader
            .collect_cells(self.program.sender.clone(), tx_fee + output_capacity)?;
        let latest_change = self.loader.load_latest_contract_change(
            self.program.destination.clone(),
            None,
            false,
        )?;
        let latest_tree = latest_change.merkle_tree();
        let program_data = self.program_data();

        let result = run(&self.config, &latest_tree, &program_data)?;
        let proof = result.generate_proof(&latest_tree)?;
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
            .config
            .type_script
            .clone()
            .as_builder()
            .args(type_id_args.pack())
            .build();

        let data = BytesOpt::new_builder()
            .set(Some(proof.serialize(&program_data)?.pack()))
            .build();
        let witness = WitnessArgs::new_builder().output_type(data).build();
        let output = CellOutput::new_builder()
            .type_(
                ScriptOpt::new_builder()
                    .set(Some(contract_type_script))
                    .build(),
            )
            .lock(contract_lock_script.clone())
            .capacity(output_capacity.pack())
            .build();
        let mut output_data = BytesMut::from(root_hash.as_slice());
        output_data.put(&blake2b_256(result.return_data.as_ref())[..]);

        let validator_cell_dep = CellDep::new_builder()
            .out_point(self.config.validator_outpoint.clone())
            .dep_type(DepType::Code.into())
            .build();

        let mut transaction_builder = TransactionBuilder::default()
            .cell_dep(SIGHASH_CELL_DEP.clone())
            .cell_dep(validator_cell_dep)
            .inputs(inputs.pack())
            .witness(witness.as_bytes().pack())
            .output(output)
            .output_data(output_data.freeze().pack());

        let capacity_left = total_capacity - tx_fee - output_capacity;
        if capacity_left >= MIN_CELL_CAPACITY {
            let sender_args = Bytes::from(self.program.sender.0.as_bytes().to_vec());
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
        let rpc_tx = rpc_types::Transaction::from(tx.data());
        Ok(TransactionReceipt {
            tx: rpc_tx,
            contract_address: Some(contract_address),
            return_data: result.return_data,
            // TODO: parse `result.logs`
            logs: Vec::new(),
        })
    }
}
