const fs = require('fs');
const process = require('process');
const xrpljs = require('xrpl-hooks');
const { submitTxn, appenv, init } = require('./common');

const hsfOVERRIDE = appenv.hsfOVERRIDE;
const hsfNSDELETE = appenv.hsfNSDELETE;

const NAMESPACE = appenv.NAMESPACE;
const CONFIG_PATH = appenv.CONFIG_PATH;

const WASM_PATH = `${appenv.WASM_DIR_PATH}/delegate.wasm`;

console.log(WASM_PATH);

let cfg;

if (process.env.DEV_MODE == 1 && !fs.existsSync(CONFIG_PATH)) {
    cfg = {
        "xrpl": {
            "address": "",
            "secret": ""
        },
        "network": ""
    }
    fs.writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2));
}
else {
    cfg = JSON.parse(fs.readFileSync(CONFIG_PATH));
}

const delegateSecret = cfg.xrpl.secret;

init(cfg.network).then(() => {
    const account = xrpljs.Wallet.fromSeed(delegateSecret)
    const binary = fs.readFileSync(WASM_PATH).toString('hex').toUpperCase();

    const hookTx = {
        Account: account.classicAddress,
        TransactionType: "SetHook",
        NetworkID: appenv.NETWORK_ID,
        Hooks:
            [{
                Hook: {
                    CreateCode: binary,
                    HookOn: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBFFFF7", //ttACCOUNT_SET
                    HookNamespace: NAMESPACE,
                    HookApiVersion: 0,
                    Flags: hsfOVERRIDE
                }
            },
            { Hook: { Flags: hsfOVERRIDE || hsfNSDELETE, CreateCode: '' } },
            { Hook: { Flags: hsfOVERRIDE || hsfNSDELETE, CreateCode: '' } },
            { Hook: { Flags: hsfOVERRIDE || hsfNSDELETE, CreateCode: '' } }]
    };

    submitTxn(delegateSecret, hookTx).then(res => { console.log(res); }).catch(console.error).finally(() => process.exit(0))
}).catch(console.error);
