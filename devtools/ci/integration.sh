#!/bin/bash

set -eu
set -x

CKB_BRANCH="v0.33.0-pre1"
CKB_CLI_VERSION="v0.34.0"
POLYJUICE_LISTEN="127.0.0.1:9214"
POLYJUICE_URL="http://${POLYJUICE_LISTEN}"

PROJECT_ROOT=$(pwd)
INTEGRATION_ROOT="$(pwd)/integration"
CKB_PID=${INTEGRATION_ROOT}/ckb.pid
POLYJUICE_PID=${INTEGRATION_ROOT}/polyjuice.pid
PATH=${PWD}/target/release:${INTEGRATION_ROOT}:${PATH}

export API_URL="http://localhost:9114"
export CKB_CLI_HOME="${INTEGRATION_ROOT}/ckb-cli-home"

# Download and start ckb
DEV_CHAIN_DIR=${INTEGRATION_ROOT}/dev-chain
rm -rf ${DEV_CHAIN_DIR}
mkdir -p ${DEV_CHAIN_DIR}
CKB_TAR_FILENAME="ckb_${CKB_BRANCH}_x86_64-unknown-linux-gnu.tar.gz"
if [ ! -f ${INTEGRATION_ROOT}/${CKB_TAR_FILENAME} ]; then
    cd ${INTEGRATION_ROOT}
    curl -L -O "https://github.com/nervosnetwork/ckb/releases/download/${CKB_BRANCH}/${CKB_TAR_FILENAME}"
    tar -xzf ${CKB_TAR_FILENAME}
fi

cp ${INTEGRATION_ROOT}/ckb_${CKB_BRANCH}_x86_64-unknown-linux-gnu/ckb ${DEV_CHAIN_DIR}
${DEV_CHAIN_DIR}/ckb --version

cd ${DEV_CHAIN_DIR}
if [ -f "${CKB_PID}" ]; then
    kill -9 `cat ${CKB_PID}` || true
    rm ${CKB_PID}
fi
rm -rf data specs *.toml
./ckb init --chain dev --ba-arg 0xc8328aabcd9b9e8e64fbc566c4385c3bdeb219d7
sed -i "s/.*value =.*/value = 200/" ./ckb-miner.toml
sed -i "s/\"info\"/\"info,ckb-script=debug\"/g" ckb.toml
sed -i "s/8114/9114/g" *.toml
sed -i "s/8115/9115/g" *.toml
./ckb run >ckb.log 2>&1 &
echo $! > ${CKB_PID}
sleep 1
CKB_BIN=${DEV_CHAIN_DIR}/ckb

rm -rf ${CKB_CLI_HOME}
mkdir -p ${CKB_CLI_HOME}
# Downlaod ckb-cli
CKB_CLI_TAR_FILENAME="ckb-cli_${CKB_CLI_VERSION}_x86_64-unknown-linux-gnu.tar.gz"
if [ ! -f ${INTEGRATION_ROOT}/${CKB_CLI_TAR_FILENAME} ]; then
    cd ${INTEGRATION_ROOT}
    curl -L -O https://github.com/nervosnetwork/ckb-cli/releases/download/${CKB_CLI_VERSION}/${CKB_CLI_TAR_FILENAME}
    tar -xzf ${INTEGRATION_ROOT}/${CKB_CLI_TAR_FILENAME}
fi

cp ${INTEGRATION_ROOT}/ckb-cli_${CKB_CLI_VERSION}_x86_64-unknown-linux-gnu/ckb-cli ${INTEGRATION_ROOT}
ckb-cli --version

# Build c contracts
cd ${PROJECT_ROOT}/c
make all-via-docker

# Deploy contracts
PRIVKEY_PATH=${INTEGRATION_ROOT}/privkey-0xc8328aabcd9b9e8e64fbc566c4385c3bdeb219d7
echo "d00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2bc" > ${PRIVKEY_PATH}

# 1. deploy always_success
${CKB_BIN} miner -C ${DEV_CHAIN_DIR} -l 1
ALWAYS_SUCCESS_TX_HASH_PATH=${INTEGRATION_ROOT}/tx_hash_always_success
ckb-cli wallet transfer \
        --privkey-path ${PRIVKEY_PATH} \
        --to-address ckt1qyqdfjzl8ju2vfwjtl4mttx6me09hayzfldq8m3a0y \
        --tx-fee 0.001 \
        --capacity 600 \
        --to-data 0x7f454c460201010000000000000000000200f3000100000078000100000000004000000000000000980000000000000005000000400038000100400003000200010000000500000000000000000000000000010000000000000001000000000082000000000000008200000000000000001000000000000001459308d00573000000002e7368737472746162002e74657874000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b000000010000000600000000000000780001000000000078000000000000000a0000000000000000000000000000000200000000000000000000000000000001000000030000000000000000000000000000000000000082000000000000001100000000000000000000000000000001000000000000000000000000000000 \
    | cut -d ':' -f 2 \
    | xargs > ${ALWAYS_SUCCESS_TX_HASH_PATH}
ALWAYS_SUCCESS_TX_HASH=$(cat ${ALWAYS_SUCCESS_TX_HASH_PATH})
${CKB_BIN} miner -C ${DEV_CHAIN_DIR} -l 4

# 2. deploy validator
${CKB_BIN} miner -C ${DEV_CHAIN_DIR} -l 1
VALIDATOR_TX_HASH_PATH=${INTEGRATION_ROOT}/tx_hash_validator
ckb-cli wallet transfer \
        --privkey-path ${PRIVKEY_PATH} \
        --to-address ckt1qyqdfjzl8ju2vfwjtl4mttx6me09hayzfldq8m3a0y \
        --tx-fee 0.01 \
        --capacity 300000 \
        --to-data-path ${PROJECT_ROOT}/c/build/validator_log \
    | cut -d ':' -f 2 \
    | xargs > ${VALIDATOR_TX_HASH_PATH}
${CKB_BIN} miner -C ${DEV_CHAIN_DIR} -l 4
VALIDATOR_TX_HASH=$(cat ${VALIDATOR_TX_HASH_PATH})
VALIDATOR_CODE_HASH=$(ckb-cli util blake2b --binary-path ${PROJECT_ROOT}/c/build/validator_log)

# 3. deploy anyone can pay
ANYONE_CAN_PAY_TX_HASH_PATH=${INTEGRATION_ROOT}/tx_hash_anyone_can_pay
ckb-cli wallet transfer \
        --privkey-path ${PRIVKEY_PATH} \
        --to-address ckt1qyqdfjzl8ju2vfwjtl4mttx6me09hayzfldq8m3a0y \
        --tx-fee 0.01 \
        --capacity 60000 \
        --to-data-path ${PROJECT_ROOT}/tests/anyone_can_pay \
    | cut -d ':' -f 2 \
    | xargs > ${ANYONE_CAN_PAY_TX_HASH_PATH}
${CKB_BIN} miner -C ${DEV_CHAIN_DIR} -l 4
ANYONE_CAN_PAY_TX_HASH=$(cat ${ANYONE_CAN_PAY_TX_HASH_PATH})
ANYONE_CAN_PAY_CODE_HASH=$(ckb-cli util blake2b --binary-path ${PROJECT_ROOT}/tests/anyone_can_pay)

cat > ${INTEGRATION_ROOT}/run_config.json << _RUN_CONFIG_
{
    "type_dep": {
        "out_point": {
            "tx_hash": "${VALIDATOR_TX_HASH}",
            "index": "0x0"
        },
        "dep_type": "code"
    },
    "type_script": {
        "code_hash": "${VALIDATOR_CODE_HASH}",
        "hash_type": "data",
        "args": "0x"
    },
    "lock_dep": {
        "out_point": {
            "tx_hash": "${ALWAYS_SUCCESS_TX_HASH}",
            "index": "0x0"
        },
        "dep_type": "code"
    },
    "lock_script": {
        "code_hash": "0x28e83a1277d48add8e72fadaa9248559e1b632bab2bd60b27955ebc4c03800a5",
        "hash_type": "data",
        "args": "0x"
    },
    "eoa_lock_dep": {
        "out_point": {
            "tx_hash": "${ANYONE_CAN_PAY_TX_HASH}",
            "index": "0x0"
        },
        "dep_type": "code"
    },
    "eoa_lock_script": {
        "code_hash": "${ANYONE_CAN_PAY_CODE_HASH}",
        "hash_type": "data",
        "args": "0x"
    }
}
_RUN_CONFIG_

# Build and start polyjuice
cd ${PROJECT_ROOT}
make prod
cd ${INTEGRATION_ROOT}
if [ -f "${POLYJUICE_PID}" ]; then
    kill -9 `cat ${POLYJUICE_PID}` || true
    rm ${POLYJUICE_PID}
fi
rm -rf data
RUST_LOG=info,polyjuice=debug polyjuice run \
        --generator ${PROJECT_ROOT}/c/build/generator \
        --db ${INTEGRATION_ROOT}/data \
        --config ${INTEGRATION_ROOT}/run_config.json \
        --listen ${POLYJUICE_LISTEN} \
        --url ${API_URL} >polyjuice.log 2>&1 &
echo $! > ${POLYJUICE_PID}
sleep 3

# Run tests
rm -rf ${INTEGRATION_ROOT}/contract-files
mkdir -p ${INTEGRATION_ROOT}/contract-files
cd ${PROJECT_ROOT}
python ./tests/test.py ${INTEGRATION_ROOT}/contract-files ${CKB_BIN} ${API_URL} ${POLYJUICE_URL}

# Clean up
kill -9 `cat ${CKB_PID}`
rm ${CKB_PID}
kill -9 `cat ${POLYJUICE_PID}`
rm ${POLYJUICE_PID}
