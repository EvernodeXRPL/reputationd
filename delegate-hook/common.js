const xrpljs = require('xrpl-hooks');
const rbc = require('xrpl-binary-codec');
const https = require('https');

const appenv = {
    hsfOVERRIDE: 1,
    hsfNSDELETE: 2,
    hfsOVERRIDE: 1,
    hfsNSDELETE: 2,
    NAMESPACE: '2BC6C2BBAC00E254AA5F2E855AD6F25BFF556EE8EEC9C82918EBCFA01FD05507',  // sha256('evernode.org|host-delegate')
    CONFIG_PATH: process.env.CONFIG_PATH || './reputationd.cfg',
    WASM_DIR_PATH: process.env.WASM_PATH || "build",
    PARAM_STATE_HOOK_KEY: '4556520100000000000000000000000000000000000000000000000000000001',
    DEFINITIONS_URL: 'https://raw.githubusercontent.com/EvernodeXRPL/evernode-resources/main/definitions/definitions.json',
    NETWORK: process.env.NETWORK || 'mainnet',
    NETWORK_ID: null
}

let api = {};

const init = async (network = null) => {
    const definitions = await getDefinitions();
    network = network ? network : appenv.NETWORK;
    const def = definitions[network];
    if (!def)
        throw `Invalid network: ${network}`;

    appenv.NETWORK_ID = def.networkID;

    api = new xrpljs.Client(def.rippledServer);
}

const getDefinitions = async () => {
    return new Promise((resolve, reject) => {
        https.get(appenv.DEFINITIONS_URL, res => {
            let data = [];
            if (res.statusCode != 200)
                reject(`Error: ${res}`);
            res.on('data', chunk => {
                data.push(chunk);
            });
            res.on('end', () => {
                resolve(JSON.parse(data));
            });
        }).on('error', err => {
            reject(`Error: ${err}`);
        });
    });
}

const fee = (txBlob) => {
    return new Promise((resolve, reject) => {
        let req = { command: 'fee' };
        if (txBlob)
            req['tx_blob'] = txBlob;

        api.request(req).then(resp => {
            resolve(resp.result.drops);
        }).catch(e => {
            reject(e);
        });
    });
};

const feeCompute = (accountSeed, txnOrg) => {
    return new Promise((resolve, reject) => {
        let txnToSend = { ...txnOrg };
        txnToSend['SigningPubKey'] = '';

        let wal = xrpljs.Wallet.fromSeed(accountSeed);
        api.prepareTransaction(txnToSend, { wallet: wal }).then(txn => {
            let ser = rbc.encode(txn);
            fee(ser).then(fees => {
                let baseDrops = fees.base_fee

                delete txnToSend['SigningPubKey']
                txnToSend['Fee'] = baseDrops + '';


                api.prepareTransaction(txnToSend, { wallet: wal }).then(txn => {
                    resolve(txn);
                }).catch(e => { reject(e); });
            }).catch(e => { reject(e); });
        }).catch(e => { reject(e); });
    });
}

const feeSubmit = (seed, txn) => {
    return new Promise((resolve, reject) => {
        feeCompute(seed, txn).then(txn => {
            api.submit(txn,
                { wallet: xrpljs.Wallet.fromSeed(seed) }).then(s => {
                    resolve(s);
                }).catch(e => { reject(e); });
        }).catch(e => { reject(e); });
    });
}

const submitTxn = (seed, txn) => {
    return new Promise((resolve, reject) => {
        api.connect().then(() => {
            feeSubmit(seed, txn).then(res => {
                if (res?.result?.engine_result === 'tesSUCCESS')
                    resolve(res?.result?.engine_result);
                else
                    reject(res);
            }).catch(e => { reject(e); });
        }).catch(e => { reject(e); });
    });
}

const getHookHashes = (account) => {
    return new Promise((resolve, reject) => {
        api.connect().then(() => {
            let req = { command: 'account_objects' };
            if (account)
                req['account'] = account;

            api.request(req).then(resp => {
                resolve(resp.result.account_objects.find(o => o.Hooks && o.Hooks.length)?.Hooks?.map(h => h?.Hook?.HookHash).filter(h => h));
            }).catch(e => {
                reject(e);
            });
        });
    });
};

module.exports = {
    init,
    submitTxn,
    getHookHashes,
    appenv
}