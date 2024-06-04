
const bson = require('bson');
const HotPocket = require('hotpocket-js-client');
const { CommonHelper } = require('./util-helper');

const DEFAULT_TIMEOUT = 120000;
const INPUT_PROTOCOLS = HotPocket.protocols;

class ContractInstanceManager {
    #ip;
    #userPort;
    #userPrivateKey;
    #hpClient;

    constructor(options = {}) {
        this.#ip = options.ip;
        this.#userPort = options.userPort;
        this.#userPrivateKey = options.userPrivateKey;
    }

    async init() {
        if (!this.#ip)
            throw "Instance IP is missing!";
        else if (!this.#userPort)
            throw "Instance user port is missing!";
        else if (!this.#userPrivateKey)
            throw "Instance user private key is missing!";

        const userKeys = await CommonHelper.generateKeys(this.#userPrivateKey, 'binary');
        console.log('My public key is: ' + Buffer.from(userKeys.publicKey).toString('hex'));

        const server = `wss://${this.#ip}:${this.#userPort}`;
        this.#hpClient = await HotPocket.createClient([server], userKeys, {
            protocol: HotPocket.protocols.bson
        });

        // Establish HotPocket connection.
        if (!await this.#hpClient.connect())
            throw `${server} connection failed.`;
    }

    async terminate() {
        if (this.#hpClient)
            await this.#hpClient.close()
    }

    async sendContractInput(input, timeoutMs = DEFAULT_TIMEOUT, protocol = HotPocket.protocols.bson) {
        return new Promise(async (resolve, reject) => {

            const inputTimer = setTimeout(() => {
                clearTimeout(inputTimer);
                this.#hpClient.clear(HotPocket.events.contractOutput);
                reject("Input timeout.");
            }, timeoutMs);

            const failure = (e) => {
                clearTimeout(inputTimer);
                this.#hpClient.clear(HotPocket.events.contractOutput);
                reject(e);
            }
            const success = (result) => {
                clearTimeout(inputTimer);
                resolve(result);
            }

            // This will get fired when contract sends an output.
            this.#hpClient.on(HotPocket.events.contractOutput, (r) => {

                r.outputs.forEach(output => {
                    let result;
                    try {
                        result = protocol === INPUT_PROTOCOLS.bson ? bson.deserialize(output) : JSON.parse(output);
                    }
                    catch (e) {
                        failure(e);
                    }
                    if (result?.type == `${input.type}Result`) {
                        if (result.status == "ok")
                            success(result.message);
                        else
                            failure(`Input failed. reason: ${result.message}`);
                    }
                });
            });

            const res = await this.#hpClient.submitContractInput(protocol === INPUT_PROTOCOLS.bson ? bson.serialize(input) : JSON.stringify(input));

            const submission = await res.submissionStatus;
            if (submission.status != "accepted")
                failure("Input submission failed. reason: " + submission.reason);
        });
    }

    async sendContractReadRequest(input, protocol = HotPocket.protocols.bson) {
        const output = await this.#hpClient.submitContractReadRequest(protocol === INPUT_PROTOCOLS.bson ? bson.serialize(input) : JSON.stringify(input));
        const result = protocol === INPUT_PROTOCOLS.bson ? bson.deserialize(output) : JSON.parse(output);
        return result?.message;
    }
}

module.exports = {
    ContractInstanceManager,
    INPUT_PROTOCOLS
}