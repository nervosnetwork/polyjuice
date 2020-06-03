use ckb_hash::{blake2b_256, new_blake2b};
use ckb_simple_account_layer::{
    run_with_context, CkbBlake2bHasher, Config, RunContext, RunProofResult, RunResult,
};
use ckb_types::{
    bytes::{BufMut, Bytes, BytesMut},
    core::{ScriptHashType, TransactionBuilder},
    packed::{
        BytesOpt, CellInput, CellOutput, OutPoint, Script, ScriptOpt, Transaction, WitnessArgs,
    },
    prelude::*,
    H160,
};
use ckb_vm::{
    registers::{A0, A1, A7},
    Error as VMError, Memory, Register, SupportMachine,
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
    ) -> Result<(RunResult, CsalRunContext), Box<dyn StdError>> {
        let meta = self.loader.load_contract_meta(destination.clone())?;
        if meta.destructed {
            return Err(format!("Contract already destructed: {:x}", destination.0).into());
        }
        let code = meta.code;
        let code_hash = blake2b_256(code.as_ref());
        let latest_change =
            self.loader
                .load_latest_contract_change(destination.clone(), None, false, false)?;
        let program = Program::new_call(sender.clone(), sender, destination, code, input, false);

        let latest_tree = latest_change.merkle_tree();
        let mut witness_data = WitnessData::new(program);
        let program_data = witness_data.program_data();

        let config: Config = (&self.run_config).into();
        log::debug!(
            "[length]: {}",
            hex::encode(&(program_data.len() as u32).to_le_bytes()[..])
        );
        log::debug!("[binary]: {}", hex::encode(program_data.as_ref()));
        let mut context = CsalRunContext::new(config, CellInput::default());
        let new_tree = SparseMerkleTree::new(*latest_tree.root(), latest_tree.store().clone());
        let result = match context.run(new_tree, witness_data.program) {
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
        // TODO: merge with context
        Ok((result, context))
    }

    pub fn call(
        &mut self,
        sender: EoaAddress,
        destination: ContractAddress,
        input: Bytes,
    ) -> Result<(Transaction, RunResult, CsalRunContext), Box<dyn StdError>> {
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
        let program = Program::new_call(sender.clone(), sender, destination, code, input, false);

        let tx_fee = ONE_CKB;
        let (mut live_cells, total_capacity) = self
            .loader
            .collect_cells(program.sender.clone(), tx_fee + MIN_CELL_CAPACITY)?;
        let out_point = OutPoint::new(latest_change.tx_hash.pack(), latest_change.output_index);
        // Should add to the head of inputs
        live_cells.insert(0, out_point);

        let inputs = live_cells
            .into_iter()
            .map(|out_point| CellInput::new(out_point, 0))
            .collect::<Vec<_>>();

        let latest_tree = latest_change.merkle_tree();
        let mut witness_data = WitnessData::new(program.clone());
        let program_data = witness_data.program_data();

        log::debug!(
            "[length]: {}",
            hex::encode(&(program_data.len() as u32).to_le_bytes()[..])
        );
        log::debug!("[binary]: {}", hex::encode(program_data.as_ref()));
        let config: Config = (&self.run_config).into();
        let mut context = CsalRunContext::new(config, inputs[0].clone());
        let new_tree = SparseMerkleTree::new(*latest_tree.root(), latest_tree.store().clone());
        let result = match context.run(new_tree, program.clone()) {
            Ok(result) => result,
            Err(err) => {
                log::warn!("Error: {:?}", err);
                return Err(err);
            }
        };
        let proof = result.generate_proof(&latest_tree)?;
        print_proof(&proof);
        let root_hash = result.committed_root_hash(&latest_tree)?;
        if context.current_contract_info().selfdestruct.is_none()
            && root_hash.as_slice() == latest_root_hash
        {
            // TODO handle value change
            return Err(String::from("Storage unchanged!").into());
        }

        // 1. cell deps
        // 2. inputs
        // 3. outputs
        let (output, output_data) =
            if let Some(ref selfdestruct_target) = context.current_contract_info().selfdestruct {
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
                let mut output_data = BytesMut::default();
                output_data.put(root_hash.as_slice());
                output_data.put(&code_hash[..]);
                (contract_live_cell, output_data.freeze())
            };
        // 4. witness
        witness_data.update(&context)?;
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
        Ok((tx.data(), result, context))
    }

    pub fn create(
        &mut self,
        sender: EoaAddress,
        code: Bytes,
    ) -> Result<(ContractAddress, Transaction, RunResult, CsalRunContext), Box<dyn StdError>> {
        let program = Program::new_create(sender.clone(), sender, code);

        // TODO: let user choose the lock
        let contract_lock_script = ALWAYS_SUCCESS_SCRIPT.clone();

        let tx_fee = ONE_CKB;
        let output_capacity = 200 * ONE_CKB;
        let (live_cells, total_capacity) = self
            .loader
            .collect_cells(program.sender.clone(), tx_fee + output_capacity)?;
        let inputs = live_cells
            .into_iter()
            .map(|out_point| CellInput::new(out_point, 0))
            .collect::<Vec<_>>();
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
        let mut context = CsalRunContext::new(config, inputs[0].clone());
        let new_tree = SparseMerkleTree::new(*latest_tree.root(), latest_tree.store().clone());
        let result = match context.run(new_tree, program.clone()) {
            Ok(result) => result,
            Err(err) => {
                log::warn!("Error: {:?}", err);
                return Err(err);
            }
        };
        let proof = result.generate_proof(&latest_tree)?;
        print_proof(&proof);
        let root_hash = result.committed_root_hash(&latest_tree)?;

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

        witness_data.return_data = context
            .current_contract_info()
            .current_return_data()
            .clone();
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
        let mut output_data = BytesMut::default();
        let code_hash = blake2b_256(
            context
                .current_contract_info()
                .current_return_data()
                .as_ref(),
        );
        output_data.put(root_hash.as_slice());
        output_data.put(&code_hash[..]);
        log::debug!(
            "code: {}",
            hex::encode(
                context
                    .current_contract_info()
                    .current_return_data()
                    .as_ref()
            )
        );
        log::debug!("code hash: {}", hex::encode(&code_hash[..]));

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
        Ok((contract_address, tx.data(), result, context))
    }
}

pub struct CsalRunContext {
    pub config: Config,
    // The transaction origin address
    pub tx_origin: EoaAddress,
    pub first_cell_input: CellInput,
    // Current running contract
    contract_index: usize,
    contracts: Vec<(ContractAddress, ContractInfo)>,
}

pub struct ContractInfo {
    pub tree: SparseMerkleTree<CkbBlake2bHasher, SmtH256, DefaultStore<SmtH256>>,
    output_index: u64,
    call_index: usize,
    // (program, logs, return_data)
    call_records: Vec<(Program, Vec<Bytes>, Bytes)>,
    pub selfdestruct: Option<Bytes>,
}

impl ContractInfo {
    pub fn new(
        tree: SparseMerkleTree<CkbBlake2bHasher, SmtH256, DefaultStore<SmtH256>>,
        output_index: u64,
    ) -> ContractInfo {
        ContractInfo {
            tree,
            output_index,
            call_index: 0,
            call_records: Vec::new(),
            selfdestruct: None,
        }
    }

    pub fn current_program(&self) -> &Program {
        &self.current_record().0
    }
    pub fn current_logs(&self) -> &Vec<Bytes> {
        &self.current_record().1
    }
    pub fn current_return_data(&self) -> &Bytes {
        &self.current_record().2
    }
    pub fn current_record(&self) -> &(Program, Vec<Bytes>, Bytes) {
        &self.call_records[self.call_index]
    }

    pub fn current_logs_mut(&mut self) -> &mut Vec<Bytes> {
        &mut self.current_record_mut().1
    }
    pub fn current_return_data_mut(&mut self) -> &mut Bytes {
        &mut self.current_record_mut().2
    }
    pub fn current_record_mut(&mut self) -> &mut (Program, Vec<Bytes>, Bytes) {
        &mut self.call_records[self.call_index]
    }
}

impl CsalRunContext {
    pub fn new(config: Config, first_cell_input: CellInput) -> CsalRunContext {
        CsalRunContext {
            config,
            tx_origin: Default::default(),
            first_cell_input,
            contract_index: 0,
            contracts: Vec::new(),
        }
    }

    pub fn destination(&self, program: &Program, output_index: u64) -> ContractAddress {
        if program.is_create() {
            let type_id_args = {
                let mut blake2b = new_blake2b();
                blake2b.update(self.first_cell_input.as_slice());
                blake2b.update(&output_index.to_le_bytes());
                let mut ret = [0; 32];
                blake2b.finalize(&mut ret);
                Bytes::from(ret[0..20].to_vec())
            };
            H160::from_slice(type_id_args.as_ref())
                .map(ContractAddress)
                .unwrap()
        } else {
            program.destination.clone()
        }
    }

    pub fn run(
        &mut self,
        tree: SparseMerkleTree<CkbBlake2bHasher, SmtH256, DefaultStore<SmtH256>>,
        program: Program,
    ) -> Result<RunResult, Box<dyn StdError>> {
        let output_index: u64 = 0;
        let new_tree = SparseMerkleTree::new(*tree.root(), tree.store().clone());
        let info = ContractInfo::new(tree, output_index);
        self.tx_origin = program.sender.clone();
        self.contract_index = 0;
        self.contracts
            .push((self.destination(&program, output_index), info));
        let witness_data = WitnessData::new(program);
        let config = self.config.clone();
        run_with_context(&config, &new_tree, &witness_data.program_data(), self)
    }

    pub fn get_contract_index(&self, address: &ContractAddress) -> Option<usize> {
        self.contracts
            .iter()
            .position(|(addr, info)| addr == address)
    }
    pub fn get_contract_info(&self, address: &ContractAddress) -> Option<&ContractInfo> {
        self.get_contract_index(address)
            .map(|index| &self.contracts[index].1)
    }
    pub fn get_contract_info_mut(
        &mut self,
        address: &ContractAddress,
    ) -> Option<&mut ContractInfo> {
        if let Some(index) = self.get_contract_index(address) {
            Some(&mut self.contracts[index].1)
        } else {
            None
        }
    }

    pub fn current_contract_address(&self) -> &ContractAddress {
        &self.contracts[self.contract_index].0
    }
    pub fn current_contract_info(&self) -> &ContractInfo {
        &self.contracts[self.contract_index].1
    }
    pub fn current_contract_info_mut(&mut self) -> &mut ContractInfo {
        &mut self.contracts[self.contract_index].1
    }
}

impl<Mac: SupportMachine> RunContext<Mac> for CsalRunContext {
    fn ecall(&mut self, machine: &mut Mac) -> Result<bool, VMError> {
        let code = machine.registers()[A7].to_u64();
        match code {
            // return
            3075 => {
                let data_address = machine.registers()[A0].to_u64();
                let data_length = machine.registers()[A1].to_u32();
                let data = load_data(machine, data_address, data_length)?;
                *self.current_contract_info_mut().current_return_data_mut() = data.into();
                // self.return_data = data.into();
                Ok(true)
            }
            // LOG{0,1,2,3,4}
            3076 => {
                let data_address = machine.registers()[A0].to_u64();
                let data_length = machine.registers()[A1].to_u32();
                let data = load_data(machine, data_address, data_length)?;
                self.current_contract_info_mut()
                    .current_logs_mut()
                    .push(data.into());
                // self.logs.push(data.into());
                Ok(true)
            }
            // SELFDESTRUCT
            3077 => {
                let data_address = machine.registers()[A0].to_u64();
                let data_length = machine.registers()[A1].to_u32();
                let data = load_data(machine, data_address, data_length)?;
                if self.current_contract_info().selfdestruct.is_some() {
                    panic!("selfdestruct twice: {:?}", self.current_contract_address());
                }
                self.current_contract_info_mut().selfdestruct = Some(data.into());
                // self.selfdestruct = Some(data.into());
                Ok(true)
            }
            // CALL
            3078 => {
                // FIXME:
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

fn load_data<Mac: SupportMachine>(
    machine: &mut Mac,
    address: u64,
    length: u32,
) -> Result<Vec<u8>, VMError> {
    let mut data = vec![0u8; length as usize];
    for (i, c) in data.iter_mut().enumerate() {
        *c = machine
            .memory_mut()
            .load8(&Mac::REG::from_u64(address).overflowing_add(&Mac::REG::from_u64(i as u64)))?
            .to_u8();
    }
    Ok(data)
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
