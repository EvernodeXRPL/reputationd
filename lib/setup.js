const { appenv } = require('./appenv');
const evernode = require('evernode-js-client');
const { ConfigHelper } = require('./config-helper');

async function setEvernodeDefaults(network, governorAddress, rippledServer, fallbackRippledServers) {
    await evernode.Defaults.useNetwork(network || appenv.NETWORK);

    if (governorAddress)
        evernode.Defaults.set({
            governorAddress: governorAddress
        });

    if (rippledServer)
        evernode.Defaults.set({
            rippledServer: rippledServer
        });

    if (fallbackRippledServers && fallbackRippledServers.length)
        evernode.Defaults.set({
            fallbackRippledServers: fallbackRippledServers
        });
}

const MAX_TX_RETRY_ATTEMPTS = 10;

class Setup {

    #getConfig(readSecret = true, includeMbConfig = true) {
        return ConfigHelper.readConfig(appenv.CONFIG_PATH, includeMbConfig ? appenv.MB_XRPL_CONFIG_PATH : null, readSecret);
    }

    #saveConfig(cfg) {
        ConfigHelper.writeConfig(cfg, appenv.CONFIG_PATH);
    }

    newConfig(address = "", secretPath = "") {
        const baseConfig = {
            version: appenv.REPUTATIOND_VERSION,
            xrpl: {
                address: address,
                secretPath: secretPath
            },
            contractInstance: {}
        };

        this.#saveConfig(baseConfig);
    }

    async prepareReputationAccount() {

        const config = this.#getConfig();
        const acc = config.xrpl;
        await setEvernodeDefaults(acc.network, acc.governorAddress, acc.rippledServer, acc.fallbackRippledServers);

        // Prepare host account.
        const hostClient = new evernode.HostClient(acc.hostAddress, acc.hostSecret);
        await hostClient.connect();

        // Update the Defaults with "xrplApi" of the client.
        evernode.Defaults.set({
            xrplApi: hostClient.xrplApi
        });

        try {
            console.log(`Preparing reputation account:${acc.address} | Reputation Hook:${hostClient.config.reputationAddress}`);
            await hostClient.prepareReputationAccount(acc.address, acc.secret, { retryOptions: { maxRetryAttempts: MAX_TX_RETRY_ATTEMPTS, feeUplift: Math.floor(acc.affordableExtraFee / MAX_TX_RETRY_ATTEMPTS) } });
            await hostClient.disconnect();
        }
        catch (e) {
            await hostClient.disconnect();
            throw e;
        }
    }

    async waitForFunds(currencyType, expectedBalance, waitPeriod = 120) {

        const config = this.#getConfig(false);
        const acc = config.xrpl;
        await setEvernodeDefaults(acc.network, acc.governorAddress, acc.rippledServer, acc.fallbackRippledServers);

        // Prepare host account.
        const hostClient = new evernode.HostClient(acc.hostAddress);

        // Update the Defaults with "xrplApi" of the client.
        evernode.Defaults.set({
            xrplApi: hostClient.xrplApi
        });

        try {
            let attempts = 0;
            let balance = 0;
            while (attempts >= 0) {
                try {
                    // In order to handle the account not found issue via catch block.
                    await hostClient.connect();

                    // Prepare reputation account.
                    const reputationAcc = new evernode.XrplAccount(acc.address);

                    await new Promise(resolve => setTimeout(resolve, 1000));
                    if (currencyType === 'NATIVE')
                        balance = Number((await reputationAcc.getInfo()).Balance) / 1000000;
                    else {
                        const lines = await reputationAcc.getTrustLines(evernode.EvernodeConstants.EVR, hostClient.config.evrIssuerAddress);
                        balance = lines.length > 0 ? Number(lines[0].balance) : 0;
                    }

                    if (balance < expectedBalance) {
                        if (++attempts <= waitPeriod)
                            continue;

                        await hostClient.disconnect();
                        throw "NOT_ENOUGH_FUNDS";
                    }

                    break;
                } catch (err) {
                    if (err.data?.error === 'actNotFound' && ++attempts <= waitPeriod) {
                        await new Promise(resolve => setTimeout(resolve, 1000));
                        continue;
                    }
                    await hostClient.disconnect();
                    throw (err.data?.error === 'actNotFound' || err === 'NOT_ENOUGH_FUNDS') ? "Funds not received within timeout." : "Error occurred in account balance check.";
                }
            }

            console.log(`${balance} ${currencyType == 'NATIVE' ? 'XAH' : 'EVR'} balance is there in your host account.`);
            await hostClient.disconnect();
        }
        catch (e) {
            await hostClient.disconnect();
            throw e;
        }
    }

    // Upgrades existing message board data to the new version.
    async upgrade() {

        // Do a simple version change in the config.
        const cfg = this.#getConfig(false, false);
        cfg.version = appenv.REPUTATIOND_VERSION;

        this.#saveConfig(cfg);

        await Promise.resolve(); // async placeholder.
    }

    async repInfo() {
        const acc = this.#getConfig(false).xrpl;
        await setEvernodeDefaults(acc.network, acc.governorAddress, acc.rippledServer, acc.fallbackRippledServers);

        const hostClient = new evernode.HostClient(acc.hostAddress);
        await hostClient.connect();

        // Update the Defaults with "xrplApi" of the client.
        evernode.Defaults.set({
            xrplApi: hostClient.xrplApi
        });

        try {
            const repInfo = await hostClient.getReputationInfo();
            const config = hostClient.config;
            await hostClient.disconnect();
            const moment = await hostClient.getMoment();

            if (!repInfo) {
                console.log('You don\'t have reputation info yet.\n  Make sure you have opted-in. If opted-in, wait until your host reporting for first reputation.');
                return;
            }
            else if (!repInfo.moment) {
                repInfo.moment = moment;
            }

            const repClient = await evernode.HookClientFactory.create(evernode.HookTypes.reputation, { config: config });
            await repClient.connect({ skipConfigs: true });

            const globalInfo = await repClient.getReputationInfo();

            await repClient.disconnect();

            console.log(JSON.stringify({ ...repInfo, reportedHostCount: globalInfo?.count ?? 0 }, null, 2));
        }
        catch (e) {
            await hostClient.disconnect();
            throw e;
        }
        finally {
            await evernode.Defaults.values.xrplApi.disconnect();
        }
    }
}

module.exports = {
    Setup
}