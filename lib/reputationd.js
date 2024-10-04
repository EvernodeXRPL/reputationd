const evernode = require('evernode-js-client');
const crypto = require('crypto');
const uuid = require('uuid');
const fs = require('fs');
const { appenv } = require('./appenv');
const { ConfigHelper } = require('./config-helper');
const { CommonHelper } = require('./util-helper');
const { ContractInstanceManager, INPUT_PROTOCOLS } = require('./contract-instance-manager');
const { LobbyManager } = require('./lobby-manager');

const ContractStatus = {
    Created: 1,
    Updated: 2,
    Deployed: 3,
    Terminated: 4
}

class ReputationD {
    #concurrencyQueue = {
        processing: false,
        queue: []
    };
    #applyFeeUpliftment = false;
    #reputationRetryDelay = 300000; // 5 mins
    #reputationRetryCount = 3;
    #feeUpliftment = 0;
    #executionTimeQuota = 0.5; // Percentage of moment size.
    #reputationRegTimeQuota = 0.5; // Percentage of (1 - executionTimeQuota) for reputation registration.
    #lobbyTimeQuota = 0.8; // Percentage of (1 - reputationRegTimeQuota) for reputation contract deployment.
    #universeSize = 64;
    #readScoreCmd = 'read_scores';
    #minReliableExecQuota = 0.2; // Minimum exec count quota from lcl to consider scores.
    #randomizationSeed = 0;

    #configPath;
    #mbXrplConfigPath;
    #instanceImage;
    #tlsCertPath;

    constructor(configPath, mbXrplConfigPath, instanceImage, tlsCertPath) {
        this.#configPath = configPath;
        this.#mbXrplConfigPath = mbXrplConfigPath;
        this.#instanceImage = instanceImage;
        this.#tlsCertPath = tlsCertPath;
    }

    async init() {
        this.#readConfig();
        if (!this.cfg.version || !this.cfg.xrpl.address || !this.cfg.xrpl.secret)
            throw "Required cfg fields cannot be empty.";

        await evernode.Defaults.useNetwork(this.cfg.xrpl.network || appenv.NETWORK);

        if (this.cfg.xrpl.governorAddress)
            evernode.Defaults.set({
                governorAddress: this.cfg.xrpl.governorAddress
            });

        if (this.cfg.xrpl.rippledServer)
            evernode.Defaults.set({
                rippledServer: this.cfg.xrpl.rippledServer
            });

        if (this.cfg.xrpl.fallbackRippledServers && this.cfg.xrpl.fallbackRippledServers.length)
            evernode.Defaults.set({
                fallbackRippledServers: this.cfg.xrpl.fallbackRippledServers
            });

        this.xrplApi = new evernode.XrplApi();
        evernode.Defaults.set({
            xrplApi: this.xrplApi
        })
        await this.xrplApi.connect();

        this.hostClient = new evernode.HostClient(this.cfg.xrpl.hostAddress, this.cfg.xrpl.hostSecret);
        await this.#connectHost();

        console.log("Using,");
        console.log("\tGovernor account " + this.cfg.xrpl.governorAddress);
        console.log("\tReputation account " + this.hostClient.config.reputationAddress);
        console.log("Using xahaud " + this.cfg.xrpl.rippledServer);

        // Get last heartbeat moment from the host info.
        let hostInfo = await this.hostClient.getRegistration();
        if (!hostInfo)
            throw "Host is not registered.";

        this.#randomizationSeed = (Buffer.from(hostInfo.uriTokenId, "hex").readUInt32BE((hostInfo.uriTokenId.length / 2) - 4) / 0xFFFFFFFF);

        this.reputationClient = await evernode.HookClientFactory.create(evernode.HookTypes.reputation, { config: this.hostClient.config });

        await this.#connectReputation({ skipConfigs: true });

        const repInfo = await this.hostClient.getReputationInfoByAddress();
        // Last registered moment n means reputation is sent in n-1 moment.
        this.lastReputationMoment = repInfo ? (repInfo.lastRegisteredMoment - 1) : 0;

        this.xrplApi.on(evernode.XrplApiEvents.DISCONNECTED, async (e) => {
            console.log(`Exiting due to server disconnect (code ${e})...`);
            process.exit(1);
        });


        this.xrplApi.on(evernode.XrplApiEvents.SERVER_DESYNCED, async (e) => {
            console.log(`Exiting due to server desync condition...`);
            process.exit(1);
        });

        this.xrplApi.on(evernode.XrplApiEvents.LEDGER, async (e) => {
            this.lastValidatedLedgerIndex = e.ledger_index;
            this.lastLedgerTime = evernode.UtilHelpers.getCurrentUnixTime('milli');
        });

        // Start queue processor job.
        this.#startReputationClockScheduler();

        // Schedule reputation jobs.
        this.#startScoreCacheScheduler();

        // Schedule reputation jobs.
        this.#startReputationSendScheduler();

        // Schedule reputation contract jobs.
        this.#startReputationContractScheduler();
    }

    #prepareHostClientFunctionOptions() {
        let options = {}
        if (this.#applyFeeUpliftment) {
            options.transactionOptions = { feeUplift: this.#feeUpliftment }
        }

        return options;
    }

    // Try to acquire the lease update lock.
    async #acquireConcurrencyQueue() {
        await new Promise(async resolve => {
            while (this.#concurrencyQueue.processing) {
                await new Promise(resolveSleep => {
                    setTimeout(resolveSleep, 1000);
                })
            }
            resolve();
        });
        this.#concurrencyQueue.processing = true;
    }

    // Release the lease update lock.
    async #releaseConcurrencyQueue() {
        this.#concurrencyQueue.processing = false;
    }

    async #queueAction(action, maxAttempts = 5, delay = 0) {
        await this.#acquireConcurrencyQueue();

        this.#concurrencyQueue.queue.push({
            callback: action,
            submissionRefs: {},
            attempts: 0,
            maxAttempts: maxAttempts,
            delay: delay
        });

        await this.#releaseConcurrencyQueue();
    }

    async #processConcurrencyQueue() {
        await this.#acquireConcurrencyQueue();

        let toKeep = [];
        for (let action of this.#concurrencyQueue.queue) {
            try {
                await action.callback(action.submissionRefs);
                this.#applyFeeUpliftment = false;
                this.#feeUpliftment = 0;
            }
            catch (e) {
                console.error(e);
                if (action.attempts < action.maxAttempts) {
                    action.attempts++;
                    console.log(`Retry attempt ${action.attempts}`);
                    if (this.cfg.xrpl.affordableExtraFee > 0 && e.status === "TOOK_LONG") {
                        this.#applyFeeUpliftment = true;
                        this.#feeUpliftment = Math.floor((this.cfg.xrpl.affordableExtraFee * action.attempts) / action.maxAttempts);
                    }
                    if (action.delay > 0) {
                        new Promise((resolve) => {
                            const checkFlagInterval = setInterval(() => {
                                if (!this.#concurrencyQueue.processing) {
                                    this.#concurrencyQueue.queue.push(action);
                                    clearInterval(checkFlagInterval);
                                    resolve();
                                }
                            }, action.delay);
                        });
                    } else
                        toKeep.push(action);
                }
                else {
                    console.error('Max retry attempts reached. Abandoned.');
                }
            }
        }
        this.#concurrencyQueue.queue = toKeep;

        await this.#releaseConcurrencyQueue();
    }

    // Connect the host and trying to reconnect in the event of account not found error.
    // Account not found error can be because of a network reset. (Dev and test nets)
    async #connect(client, options = null) {
        let attempts = 0;
        // eslint-disable-next-line no-constant-condition
        while (true) {
            try {
                attempts++;
                const ret = options ? await client.connect(options) : await client.connect();
                if (ret)
                    break;
            } catch (error) {
                if (error?.data?.error === 'actNotFound') {
                    let delaySec;
                    // The maximum delay will be 5 minutes.
                    if (attempts > 150) {
                        delaySec = 300;
                    } else {
                        delaySec = 2 * attempts;
                    }
                    console.log(`Network reset detected. Attempt ${attempts} failed. Retrying in ${delaySec}s...`);
                    await new Promise(resolve => setTimeout(resolve, delaySec * 1000));
                } else
                    throw error;
            }
        }
    }

    async #connectHost() {
        await this.#connect(this.hostClient, { reputationAddress: this.cfg.xrpl.address, reputationSecret: this.cfg.xrpl.secret });
    }

    async #connectReputation(options = {}) {
        await this.#connect(this.reputationClient, options);
    }

    async #startReputationClockScheduler() {
        const timeout = appenv.REPUTATIOND_SCHEDULER_INTERVAL_SECONDS * 1000; // Seconds to millisecs.

        const scheduler = async () => {
            await this.#processConcurrencyQueue();
            setTimeout(async () => {
                await scheduler();
            }, timeout);
        };

        setTimeout(async () => {
            await scheduler();
        }, timeout);
    }

    async #startReputationSendScheduler() {
        const momentSize = this.hostClient.config.momentSize;

        const timeout = momentSize * 1000; // Converting seconds to milliseconds.

        const scheduler = async () => {
            setTimeout(async () => {
                await scheduler();
            }, timeout);
            await this.#sendReputations();
        };

        const momentStartTimestamp = await this.hostClient.getMomentStartIndex();
        const currentTimestamp = evernode.UtilHelpers.getCurrentUnixTime();
        const currentMoment = await this.hostClient.getMoment();

        // Set time relative to current passed time.
        const timeQuota = momentSize * (1 - this.#executionTimeQuota);
        const upperBound = Math.floor(momentStartTimestamp + momentSize - (timeQuota * (1 - this.#reputationRegTimeQuota)));
        const idealLowerBound = Math.floor(momentStartTimestamp + momentSize - timeQuota);
        const lowerBound = Math.min(idealLowerBound + 2, upperBound); // Give 2 second buffer for reputation sending.

        let startTimestamp = Math.floor(lowerBound + (this.#randomizationSeed * ((upperBound - lowerBound) * 0.9)));

        // If already registered for this moment, Schedule for next moment.
        if (this.lastReputationMoment === currentMoment)
            startTimestamp += momentSize;

        if (currentTimestamp > startTimestamp) {
            if (currentTimestamp < upperBound) {
                console.log(`Reputation send will be done now since we are in the window.`);
                setTimeout(async () => {
                    await this.#createReputationContract();
                }, 0);
            }
            startTimestamp += momentSize;
        }

        const startTimeout = (startTimestamp - currentTimestamp) * 1000;
        console.log(`Next Reputation sender scheduled to start in ${startTimeout} milliseconds.`);

        setTimeout(async () => {
            await scheduler();
        }, startTimeout);
    }

    async #startScoreCacheScheduler() {
        const momentSize = this.hostClient.config.momentSize;

        const timeout = momentSize * 1000; // Converting seconds to milliseconds.

        const scheduler = async () => {
            setTimeout(async () => {
                await scheduler();
            }, timeout);
            await this.#cacheScores();
        };

        const momentStartTimestamp = await this.hostClient.getMomentStartIndex();
        const currentTimestamp = evernode.UtilHelpers.getCurrentUnixTime();

        // Set time relative to current passed time.
        const timeQuota = momentSize * (1 - this.#executionTimeQuota);
        const lowerBound = Math.floor(momentStartTimestamp + momentSize - timeQuota);
        var startTimestamp = lowerBound;

        if (currentTimestamp > startTimestamp)
            startTimestamp += momentSize;

        const startTimeout = (startTimestamp - currentTimestamp) * 1000;
        console.log(`Reputation score cache scheduled to start in ${startTimeout} milliseconds.`);

        setTimeout(async () => {
            await scheduler();
        }, startTimeout);
    }

    async #startReputationContractScheduler() {
        const momentSize = this.hostClient.config.momentSize;

        const timeout = momentSize * 1000; // Converting seconds to milliseconds.

        const scheduler = async () => {
            setTimeout(async () => {
                await scheduler();
            }, timeout);
            await this.#createReputationContract();
        };

        const momentStartTimestamp = await this.hostClient.getMomentStartIndex();
        const currentTimestamp = evernode.UtilHelpers.getCurrentUnixTime();
        const currentMoment = await this.hostClient.getMoment();

        const timeQuota = momentSize * (1 - this.#executionTimeQuota);
        const lowerBound = Math.floor(momentStartTimestamp + momentSize - (timeQuota * (1 - this.#reputationRegTimeQuota)));
        const upperBound = Math.floor(lowerBound + ((momentStartTimestamp + momentSize - lowerBound) * this.#lobbyTimeQuota));

        let startTimestamp = Math.floor(lowerBound + (this.#randomizationSeed * ((upperBound - lowerBound) * 0.8)));

        if (currentTimestamp > startTimestamp) {
            if (currentTimestamp < upperBound && this.lastReputationMoment === currentMoment) {
                console.log(`Reputation contract creation will be done now since we are in the window.`);
                setTimeout(async () => {
                    await this.#createReputationContract();
                }, 0);
            }
            startTimestamp += momentSize;
        }

        const startTimeout = (startTimestamp - currentTimestamp) * 1000;
        console.log(`Next reputation contract creation scheduled to start in ${startTimeout} milliseconds.`);

        setTimeout(async () => {
            await scheduler();
        }, startTimeout);
    }

    async #getUniverseInfo(moment) {
        if (!this.hostClient.reputationAcc)
            return null;

        const orderInfo = await this.reputationClient.getReputationOrderByAddress(this.hostClient.xrplAcc.address, moment);

        if (!orderInfo || !('orderedId' in orderInfo))
            return null;

        return {
            universeIndex: Math.floor(orderInfo.orderedId / this.#universeSize)
        };
    }

    async #getInstancesInUniverse(universeIndex, moment) {
        const minOrderedId = universeIndex * this.#universeSize;
        return (await Promise.all(Array.from({ length: this.#universeSize }, (_, i) => i + minOrderedId).map(async (orderedId) => {
            const repInfo = await this.reputationClient.getReputationContractInfoByOrderedId(orderedId, moment);
            if (!repInfo)
                return null;

            return repInfo.contract;
        }))).filter(i => i);
    }

    // Find the universe id and generate contract id.
    #generateContractId(universeIndex) {
        const buf = Buffer.alloc(4, 0);
        buf.writeUint32LE(universeIndex);

        // Generate a hash from the seed
        const hash = crypto.createHash('sha1').update(buf.toString('hex')).digest('hex');
        // Use a portion of the hash to generate a random UUID
        const id = uuid.v4({
            random: Buffer.from(hash, 'hex')
        });

        return id;
    }

    async #upgradeContract(instance, unl, peers) {
        let lobbyMgr;
        try {
            lobbyMgr = new LobbyManager({
                ip: instance.domain,
                userPort: instance.user_port,
                userPrivateKey: instance.owner_privatekey
            });

            await lobbyMgr.init();
            await lobbyMgr.upgradeContract(instance, unl, peers);

            if (lobbyMgr)
                lobbyMgr.terminate();
            console.log(`Contract bundle uploaded!`);
        } catch (e) {
            if (lobbyMgr)
                lobbyMgr.terminate();
            throw e;
        }
    }

    #verifyTlsCertificate() {
        const certFile = fs.readFileSync(this.#tlsCertPath, 'utf8');
        const cert = new crypto.X509Certificate(certFile);

        const certInfo = {
            subject: cert.subject,
            issuer: cert.issuer,
            validFrom: cert.validFrom,
            validTo: cert.validTo,
        };

        const currentDate = new Date();
        const validFrom = new Date(certInfo.validFrom);
        const validTo = new Date(certInfo.validTo);

        if (currentDate >= validFrom && currentDate <= validTo)
            return 'VALID';
        else
            return 'EXPIRED';
    }

    async #auditInstance() {
        if (!this.cfg.contractInstance?.domain || !this.cfg.contractInstance?.user_port) {
            console.error("No domain or user port.");
            return false;
        }

        let success = true;

        let lobbyMgr;
        try {
            lobbyMgr = new LobbyManager({
                ip: this.cfg.contractInstance.domain,
                userPort: this.cfg.contractInstance.user_port,
                userPrivateKey: this.cfg.contractInstance.owner_privatekey
            });

            await lobbyMgr.init();
            success = true;
        }
        catch (e) {
            console.error('Error occurred auditing the instance:', e);
            success = false;
        }
        finally {
            if (lobbyMgr)
                lobbyMgr.terminate();
        }

        return success;
    }

    // Create and setup reputation contract.
    async #createReputationContract() {
        const scheduledMoment = await this.hostClient.getMoment();

        await this.#queueAction(async (submissionRefs) => {
            let curMoment = await this.reputationClient.getMoment();
            let momentStartTimestamp = await this.hostClient.getMomentStartIndex();
            const momentSize = this.hostClient.config.momentSize;
            let createdMoment = this.cfg.contractInstance?.created_moment ?? -1;

            // If we have a contract created in last moment which was in updated state.
            // And we are still just passed the last reputation moment, we still consider contract creation.
            if (createdMoment === (curMoment - 1) && //this.cfg.contractInstance.status === ContractStatus.Updated &&
                (this.lastReputationMoment + 1) === curMoment &&
                (evernode.UtilHelpers.getCurrentUnixTime() - momentStartTimestamp) < (momentSize * (1 - this.#executionTimeQuota))) {
                console.log(`We are in the moment ${curMoment} but still haven't deployed.`);
                curMoment--;
                momentStartTimestamp -= momentSize;
            }

            const universeInfo = await this.#getUniverseInfo(curMoment + 1);

            if (!universeInfo) {
                console.log(`Skipping reputation contract preparation since there's no universe info for the moment ${curMoment + 1}.`);
                return;
            }

            if (scheduledMoment != curMoment) {
                console.log(`Skipping since scheduled moment has passed. Scheduled in ${scheduledMoment}, Current moment ${curMoment}.`);
                return;
            }
            else if (this.lastReputationMoment !== curMoment) {
                console.log(`Skipping reputation contract preparation since not registered for the moment ${curMoment + 1}.`);
                return;
            }

            console.log(`Preparing reputation contract for the Moment ${curMoment + 1}...`);

            let acquireSentMoment = this.cfg.contractInstance?.transaction ? (this.cfg.contractInstance?.acquire_sent_moment ?? -1) : -1;

            if (curMoment > createdMoment) {
                const tenantClient = new evernode.TenantClient(this.hostClient.reputationAcc.address, this.hostClient.reputationAcc.secret);
                await tenantClient.connect();

                submissionRefs.refs ??= [{}, {}];
                // Check again wether the transaction is validated before retry.
                const txHash1 = submissionRefs?.refs[0]?.submissionResult?.result?.tx_json?.hash;
                let retry = true;
                if (txHash1) {
                    const txResponse = await tenantClient.xrplApi.getTransactionValidatedResults(txHash1);
                    if (txResponse && txResponse.code === "tesSUCCESS") {
                        console.log('Transaction is validated and success, Retry skipped!');
                        retry = false;
                    }
                }

                if (retry) {
                    await tenantClient.prepareAccount({ submissionRef: submissionRefs?.refs[0], ...this.#prepareHostClientFunctionOptions() });
                }

                // Check again wether the transaction is validated before retry.
                const txHash2 = submissionRefs?.refs[1]?.submissionResult?.result?.tx_json?.hash;
                retry = true;
                if (txHash2) {
                    const txResponse = await tenantClient.xrplApi.getTransactionValidatedResults(txHash2);
                    if (txResponse && txResponse.code === "tesSUCCESS") {
                        console.log('Transaction is validated and success, Retry skipped!')
                        retry = false;
                    }
                }

                if (retry) {
                    if (curMoment > createdMoment ||
                        curMoment > acquireSentMoment) {
                        console.log(`Acquiring the reputation contract instance...`);

                        const ownerKeys = await CommonHelper.generateKeys();
                        const contractId = this.#generateContractId(universeInfo.universeIndex);

                        let requirement = {
                            owner_pubkey: ownerKeys.publicKey,
                            contract_id: contractId,
                            image: this.#instanceImage,
                            config: {}
                        };

                        // Update the registry with the active instance count.
                        const transaction = await tenantClient.acquireLeaseSubmit(this.hostClient.xrplAcc.address, requirement, { submissionRef: submissionRefs?.refs[1], ...this.#prepareHostClientFunctionOptions() });
                        if (!transaction)
                            throw 'Error on acquire submit';

                        acquireSentMoment = await this.reputationClient.getMoment();

                        this.cfg.contractInstance = {
                            transaction: transaction,
                            acquire_sent_moment: acquireSentMoment,
                            owner_privatekey: ownerKeys.privateKey,
                            status: ContractStatus.AcquireSent
                        };
                        this.#persistConfig();
                    }

                    const result = await tenantClient.watchAcquireResponse(this.cfg.contractInstance.transaction);
                    createdMoment = await this.reputationClient.getMoment();

                    // Assign ip to domain and outbound_ip for instance created from old sashimono version.
                    if ('ip' in result.instance) {
                        result.instance.domain = result.instance.ip;
                        delete result.instance.ip;
                    }

                    console.log('Reputation contract created in instance', result.instance);

                    this.cfg.contractInstance = {
                        ...result.instance,
                        created_moment: createdMoment,
                        owner_privatekey: this.cfg.contractInstance.owner_privatekey,
                        status: ContractStatus.Created
                    };
                    this.#persistConfig();

                    console.log(`Waiting 10 seconds until instance is ready...`);
                    await new Promise(resolve => setTimeout(resolve, 10000));
                }

                await tenantClient.disconnect();
            }
            else {
                console.log(`Skipping acquire since there is already created instance for the moment ${curMoment + 1}.`);
            }

            if (curMoment === createdMoment) {

                if (this.cfg.contractInstance.status === ContractStatus.Created) {
                    if (await this.#auditInstance()) {
                        // Set reputation contract info in domain.
                        console.log(`Updating host reputation domain info...`);
                        await this.hostClient.setReputationContractInfo(this.cfg.contractInstance.peer_port, this.cfg.contractInstance.pubkey, curMoment + 1);
                        console.log(`Updated host reputation domain info.`);

                        // Mark as updated.
                        this.cfg.contractInstance.status = ContractStatus.Updated;
                        this.#persistConfig();
                    }
                    else {
                        console.log(`Skipping contract info update since instance audit has failed.`);
                        return;
                    }
                }

                if (this.cfg.contractInstance.status === ContractStatus.Updated) {
                    // Wait for some time to let others to prepare.
                    const currentTimestamp = evernode.UtilHelpers.getCurrentUnixTime();

                    const timeQuota = momentSize * (1 - this.#executionTimeQuota);
                    const upperBound = Math.floor(momentStartTimestamp + momentSize);
                    const lowerBound = Math.floor(momentStartTimestamp + momentSize - (timeQuota * (1 - this.#reputationRegTimeQuota)));
                    const startTimestamp = Math.floor(lowerBound + ((upperBound - lowerBound) * this.#lobbyTimeQuota));

                    let startTimeout = 0;
                    if (startTimestamp > currentTimestamp)
                        startTimeout = (startTimestamp - currentTimestamp) * 1000;

                    console.log(`Waiting ${startTimeout} milliseconds until other hosts are ready.`);
                    await new Promise((resolve) => setTimeout(resolve, startTimeout));

                    const instances = await this.#getInstancesInUniverse(universeInfo.universeIndex, curMoment + 1);
                    const unl = instances.map(p => `${p.pubkey}`);
                    const peers = instances.map(p => `${p.domain}:${p.peerPort}`);

                    console.log(`Upgrading the reputation contract instance.`);
                    await this.#upgradeContract(this.cfg.contractInstance, unl, peers);
                    console.log(`Reputation contract instance upgraded.`);

                    // Mark as deployed.
                    this.cfg.contractInstance.status = ContractStatus.Deployed;
                    this.#persistConfig();
                }
            }
            else {
                console.log(`Skipping deploy since instance is not created in the moment ${curMoment}.`)
            }
        });
    }

    async #cacheScores() {
        let valid = true;
        if (!this.cfg.contractInstance?.domain || !this.cfg.contractInstance?.user_port) {
            delete this.cfg.scores;
            valid = false;
        }
        else {
            let instanceMgr;
            try {
                instanceMgr = new ContractInstanceManager({
                    ip: this.cfg.contractInstance.domain,
                    userPort: this.cfg.contractInstance.user_port,
                    userPrivateKey: this.cfg.contractInstance.owner_privatekey
                });

                await instanceMgr.init();
                const res = await instanceMgr.sendContractReadRequest({ command: this.#readScoreCmd }, INPUT_PROTOCOLS.json);
                const stat = await instanceMgr.getContractStat();
                if ((stat.ledgerSeqNo * this.#minReliableExecQuota) > (res?.execCount ?? 0)) {
                    console.error("Not a reliable score. We haven't executed the contract minimum rounds required.");
                    delete this.cfg.scores;
                    valid = false;
                }

                if (valid) {
                    console.log(`Caching reputation ${res?.scores ? 'with scores' : 'without scores'}...`);
                    const buffer = await this.hostClient.prepareHostReputationScores(appenv.SCORE_VERSION, stat.currentUnl?.length ?? 0, res?.scores);
                    this.cfg.scores = { moment: this.cfg.contractInstance?.created_moment, scoreBufHex: buffer?.toString('hex') };
                }
            } catch (e) {
                console.error('Error occurred while reading the scores:', e);
            }
            finally {
                if (instanceMgr)
                    await instanceMgr.terminate();
            }
        }

        this.#persistConfig();
    }

    #checkRequirements() {
        // Check for ipv4 support
        console.log('Checking IPV4 support...');
        const hasIPv4 = CommonHelper.hasIPv4();
        if (!hasIPv4) {
            console.error('IPv4 support is required to be a Evernode host and participate in reputation.');
            return false;
        }

        console.log('Checking version compatibility...');
        if (evernode.Defaults.values.minVersions?.reputationD) {
            const components = this.cfg.version.split('.');
            const major = components[0];
            const minor = components[1];
            const patch = components[2];
            const minComponents = evernode.Defaults.values.minVersions?.reputationD.split('.');
            const minMajor = minComponents[0];
            const minMinor = minComponents[1];
            const minPatch = minComponents[2];
            let outdated = true;
            if (major > minMajor)
                outdated = false;
            else if (major === minMajor && minor > minMinor)
                outdated = false;
            else if (major === minMajor && minor === minMinor && patch >= minPatch)
                outdated = false;
            if (outdated) {
                console.error(`ReputationD version is outdate. Found: ${this.cfg.version}, Required: ${evernode.Defaults.values.minVersions?.reputationD}`);
                return false;
            }
        }

        console.log('Checking SSL certificate validity...');
        try {
            const certStatus = this.#verifyTlsCertificate();
            if (certStatus !== 'VALID') {
                console.error(`-------------------------------------------------------`);
                console.error(`--  Your SSL certificate has expired, Please renew!  --`);
                console.error(`-------------------------------------------------------`);
                return false;
            }
        }
        catch (e) {
            console.error(e);
            console.error(`---------------------------------------------`);
            console.error(`--  Error is SSL certificate verification  --`);
            console.error(`---------------------------------------------`);
            return false;
        }

        console.log('All requirement checks passed.');
        return true;
    }

    // Reputation sender.
    async #sendReputations() {
        const scheduledMoment = await this.hostClient.getMoment();

        await this.#queueAction(async (submissionRefs) => {
            // Remove previous instance if exists.
            let createdMoment = this.cfg.contractInstance?.created_moment ?? -1;
            if (createdMoment != -1 && this.cfg.contractInstance?.name && this.cfg.contractInstance.status !== ContractStatus.Terminated) {
                console.log(`Terminating existing instance ${this.cfg.contractInstance?.name}.`);
                var tenantClient;
                try {
                    tenantClient = new evernode.TenantClient(this.hostClient.reputationAcc.address, this.hostClient.reputationAcc.secret);
                    await tenantClient.connect();
                    await tenantClient.terminateLease(this.cfg.contractInstance?.name);

                    // Mark as terminated.
                    this.cfg.contractInstance.status = ContractStatus.Terminated;
                    this.#persistConfig();
                }
                catch (err) {
                    console.log(`Error terminating the instance ${this.cfg.contractInstance?.name}.`, err);
                }
                finally {
                    if (tenantClient)
                        await tenantClient.disconnect();
                }
            }

            // Skip if host is not registered.
            const hostInfo = await this.hostClient.getRegistration();
            if (!hostInfo.active) {
                console.log(`Skipping reputation sender since host is not active.`);
                return;
            }

            const lines = await this.hostClient.reputationAcc.getTrustLines(evernode.EvernodeConstants.EVR, this.hostClient.config.evrIssuerAddress);
            if (lines.length == 0 || parseFloat(lines[0].balance) < this.cfg.xrpl.hostLeaseAmount) {
                console.log(`Skipping reputation sender due to insufficient EVR balance in the reputation account.`);
                return;
            }

            const eligible = this.#checkRequirements();
            if (!eligible) {
                console.log(`Skipping reputation sender due to ineligibility for reputation.`);
                return;
            }

            const currentMoment = await this.hostClient.getMoment();

            if (scheduledMoment == currentMoment) {
                // Sending reputations every moment.
                if (this.lastReputationMoment === 0 || currentMoment !== this.lastReputationMoment) {
                    submissionRefs.refs ??= [{}];
                    // Check again wether the transaction is validated before retry.
                    const txHash = submissionRefs?.refs[0]?.submissionResult?.result?.tx_json?.hash;
                    if (txHash) {
                        const txResponse = await this.hostClient.xrplApi.getTransactionValidatedResults(txHash);
                        if (txResponse && txResponse.code === "tesSUCCESS") {
                            console.log('Transaction is validated and success, Retry skipped!')
                            return;
                        }
                    }

                    let scoreRes = null;
                    const createdMoment = this.cfg.scores?.moment ?? -2;
                    if (currentMoment === (createdMoment + 1) && this.cfg.scores)
                        scoreRes = this.cfg.scores;

                    console.log(`Reporting reputations at Moment ${currentMoment} ${(!scoreRes?.scoreBufHex || scoreRes?.scoreBufHex?.length === 2) ? 'without' : 'with'} scores...`);

                    try {
                        const bufHex = scoreRes?.scoreBufHex ?? (await this.hostClient.prepareHostReputationScores(appenv.SCORE_VERSION, 0, null))?.toString('hex');
                        await this.hostClient.sendReputations(bufHex, { submissionRef: submissionRefs?.refs[0], ...this.#prepareHostClientFunctionOptions() });
                        this.lastReputationMoment = await this.hostClient.getMoment();
                    }
                    catch (err) {
                        if (err.code === 'tecHOOK_REJECTED') {
                            console.log("Reputation rejected by the hook.");
                        }
                        else {
                            console.log("Reputation tx error", err);
                            throw err;
                        }
                    }
                }
            }
            else {
                console.log(`Skipping reputation sender since scheduled moment has passed. Scheduled in ${scheduledMoment}, Current moment ${currentMoment}.`);
            }

        }, this.#reputationRetryCount, this.#reputationRetryDelay);
    }

    #readConfig() {
        this.cfg = ConfigHelper.readConfig(this.#configPath, this.#mbXrplConfigPath, true);
    }

    #persistConfig() {
        ConfigHelper.writeConfig(this.cfg, this.#configPath);
    }
}

module.exports = {
    ReputationD
}
