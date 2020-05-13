use bincode::{deserialize, serialize};
use ckb_jsonrpc_types::{OutPoint, Uint32};
use ckb_types::{bytes::Bytes, packed, prelude::*, H160, H256, U256};
use rocksdb::{WriteBatch, DB};
use std::collections::{HashMap, HashSet};
use std::iter::FromIterator;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use super::{Key, KeyType, Loader, Value};
use crate::rpc_client::HttpRpcClient;

pub struct Indexer {
    pub db: Arc<DB>,
    pub loader: Loader,
    pub client: HttpRpcClient,
}

impl Indexer {
    pub fn from(db: Arc<DB>, ckb_uri: &str) -> Self {
        let loader = Loader::new(Arc::clone(&db), ckb_uri).unwrap();
        Indexer {
            db,
            loader,
            client: HttpRpcClient::new(ckb_uri.to_string()),
        }
    }

    // Ideally this should never return. The caller is responsible for wrapping
    // it into a separate thread.
    pub fn index(&mut self) -> Result<(), String> {
        Ok(())
    }
}
