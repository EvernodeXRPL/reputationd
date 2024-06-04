const process = require('process');
const path = require('path');

let appenv = {
    IS_DEV_MODE: process.env.REPUTATIOND_DEV === "1",
    FILE_LOG_ENABLED: process.env.REPUTATIOND_FILE_LOG === "1",
    DATA_DIR: process.env.REPUTATIOND_DATA_DIR || __dirname,
    INSTANCE_IMAGE: 'evernodedev/reputation:hp.latest-ubt.20.04',
}

appenv = {
    ...appenv,
    CONFIG_PATH: appenv.DATA_DIR + '/reputationd.cfg',
    LOG_PATH: appenv.DATA_DIR + '/log/reputationd.log',
    REPUTATIOND_VERSION: '0.8.3',
    REPUTATIOND_SCHEDULER_INTERVAL_SECONDS: 2,
    MB_XRPL_CONFIG_PATH: path.join(appenv.DATA_DIR, '../') + "mb-xrpl/mb-xrpl.cfg",
}

Object.freeze(appenv);

module.exports = {
    appenv
}