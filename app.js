const process = require('process');
// Uncaught Exception Handling.
process.on('uncaughtException', (err) => {
    process.removeAllListeners('uncaughtException');
    process.removeAllListeners('unhandledRejection');
    console.error('Unhandled exception occurred:', err?.message);
    console.error('Stack trace:', err?.stack);
    console.log("REPUTATIOND_EXITED");
    process.exit(1);
});

// Unhandled Rejection Handling.
process.on('unhandledRejection', (reason, promise) => {
    process.removeAllListeners('unhandledRejection');
    process.removeAllListeners('uncaughtException');
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    console.log("REPUTATIOND_EXITED");
    process.exit(1);
});

const logger = require('./lib/logger');
const { appenv } = require('./lib/appenv');
const { Setup } = require('./lib/setup');
const { ReputationD } = require('./lib/reputationd');

async function main() {

    if (process.argv[2] === 'version') {
        console.log(appenv.REPUTATIOND_VERSION);
    }

    if (process.argv.length >= 3) {
        try {
            if (process.argv.length >= 5 && process.argv[2] === 'new') {
                const accountAddress = process.argv[3];
                const accountSecretPath = process.argv[4];
                const setup = new Setup();
                setup.newConfig(accountAddress, accountSecretPath);
            }
            else if (process.argv.length >= 4 && process.argv[2] === 'wait-for-funds') {
                await new Setup().waitForFunds(process.argv[3], parseFloat(process.argv[4]));
            }
            else if (process.argv.length >= 2 && process.argv[2] === 'prepare') {
                await new Setup().prepareReputationAccount();
            } else if (process.argv.length >= 4 && process.argv[2] === 'update-config') {
                // TODO: Remove this in 0.8.4.
            }
            else if (process.argv.length >= 3 && process.argv[2] === 'upgrade') {
                await new Setup().upgrade();
            }
            else if (process.argv.length === 3 && process.argv[2] === 'repinfo') {
                await new Setup().repInfo();
            }
            else if (process.argv[2] === 'help') {
                console.log(`Usage:
        node index.js - Run message board.
        node index.js version - Print version.
        node index.js new [address] [secretPath] - Create new config files.
        node index.js wait-for-funds [currencyType] [expectedBalance] - Wait until the funds are received.
        node index.js upgrade [governorAddress] - Upgrade message board data.
        node index.js help - Print help.`);
            }
            else {
                throw "Invalid args.";
            }
        }
        catch (err) {
            process.removeAllListeners('uncaughtException');
            process.removeAllListeners('unhandledRejection');

            // If error is a RippledError show internal error message, Otherwise show err.
            console.log(err?.data?.error_message || err);
            console.log("REPUTATIOND_EXITED");
            process.exit(1);
        }
    }
    else {
        try {
            // Logs are formatted with the timestamp and a log file will be created inside log directory.
            logger.init(appenv.LOG_PATH, appenv.FILE_LOG_ENABLED);

            console.log('Starting the Evernode Xahau reputationd.' + (appenv.IS_DEV_MODE ? ' (in dev mode)' : '') + ' --- patch applied ---');
            console.log('Data dir: ' + appenv.DATA_DIR);
            console.log('Using message board config: ' + appenv.MB_XRPL_CONFIG_PATH);

            const rep = new ReputationD(appenv.CONFIG_PATH, appenv.MB_XRPL_CONFIG_PATH, appenv.INSTANCE_IMAGE);
            await rep.init();
        }
        catch (err) {
            process.removeAllListeners('uncaughtException');
            process.removeAllListeners('unhandledRejection');

            // If error is a RippledError show internal error message, Otherwise show err.
            console.log(err?.data?.error_message || err);
            console.log("Evernode ReputationD exiting with error.");
            console.log("REPUTATIOND_EXITED");
            process.exit(1);
        }
    }
}

main().then(() => {
    process.removeAllListeners('uncaughtException');
    process.removeAllListeners('unhandledRejection');

    console.log("REPUTATIOND_SUCCESS");
}).catch((e) => {
    process.removeAllListeners('uncaughtException');
    process.removeAllListeners('unhandledRejection');

    console.error(e);
    console.log("REPUTATIOND_EXITED");
    process.exit(1);
});
