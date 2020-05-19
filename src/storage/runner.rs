use ckb_types::bytes::Bytes;
use std::sync::Arc;

use super::{db_get, value, Key, KeyType, Loader};
use crate::rpc_client::HttpRpcClient;
use crate::types::{
    ContractAddress, ContractChange, ContractCode, EoaAddress, Program, WitnessData,
};

pub struct Runner {
    pub loader: Loader,
    pub program: Program,
}

impl Runner {
    pub fn new(loader: Loader, program: Program) -> Runner {
        Runner { loader, program }
    }

    pub fn static_call(&self) -> Result<Bytes, String> {
        Err(format!("TODO: Runner::static_call"))
    }
    pub fn call(&self) -> Result<Bytes, String> {
        Err(format!("TODO: Runner::call"))
    }
}
