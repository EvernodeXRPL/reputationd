
const { CommonHelper } = require('./util-helper');
const WebSocket = require('ws');
const sodium = require('libsodium-wrappers');
const dns = require('dns').promises;

const DEFAULT_TIMEOUT = 120000;

class LobbyManager {
    #ip;
    #userPort;
    #userPrivateKey;
    #userKeys;
    #wsClient;

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

        this.#userKeys = await CommonHelper.generateKeys(this.#userPrivateKey, 'binary');
        console.log('My public key is: ' + Buffer.from(this.#userKeys.publicKey).toString('hex'));

        try {
            const result = await dns.lookup(this.#ip, { family: 4 });
            if (result?.address && result?.family === 4)
                this.#ip = result.address;
            else
                throw `Host is not supporting IPV4...`;

        } catch (error) {
            throw `Error occurred in looking up IPV4 address: ${error}`;
        }
        await new Promise((resolve, reject) => {
            const connectTimer = setTimeout(() => {
                clearTimeout(connectTimer);
                reject("Connection timeout.");
            }, 60000);

            const server = `wss://${this.#ip}:${this.#userPort}`;
            this.#wsClient = new WebSocket(server, {
                rejectUnauthorized: false
            });

            this.#wsClient.on('open', () => {
                console.log('Connection opened.');
                clearTimeout(connectTimer);
                resolve();
            });

            this.#wsClient.on('error', (err) => {
                console.error('Connection error.', err);
                clearTimeout(connectTimer);
                reject(err);
            });
        })
    }

    terminate() {
        if (this.#wsClient)
            this.#wsClient.close()
    }

    // Handle received messages with appropriate actions.
    #handleMessage(message) {
        const msg = JSON.parse(message);
        if (msg.errorCode) {
            throw msg.errorCode;
        }
        else {
            switch (msg.type) {
                case 'upgrade':
                    if (msg.status === 'SUCCESS')
                        return true;
                    else
                        throw msg.data ?? 'UNKNOWN_ERROR';
                default:
                    throw 'UNHANDLED_MESSAGE';
            }
        }
    }

    async upgradeContract(instanceDetails, unl, peers, timeoutMs = DEFAULT_TIMEOUT) {
        return new Promise(async (resolve, reject) => {
            const inputTimer = setTimeout(() => {
                clearTimeout(inputTimer);
                reject("Input timeout.");
            }, timeoutMs);

            const failure = (e) => {
                clearTimeout(inputTimer);
                reject(e);
            }

            const success = (result) => {
                clearTimeout(inputTimer);
                resolve(result);
            }

            if (!this.#wsClient)
                failure('Web socket connection is not initiated');

            try {
                await sodium.ready;

                // This will get fired when contract sends an output.
                this.#wsClient.on('message', (data) => {
                    console.log('Received from server:', data.toString());
                    try {
                        const res = this.#handleMessage(data);
                        if (res)
                            success('CONTRACT_UPGRADED');
                        else
                            throw 'UNKNOWN_ERROR'
                    }
                    catch (e) {
                        failure(e);
                    }
                });

                console.log('Sending upgrade request...');
                console.log('Signing the message...');
                const message = JSON.stringify({
                    type: 'upgrade',
                    unl: unl,
                    peers: peers,
                    instanceDetails: instanceDetails
                });
                const messageUint8 = sodium.from_string(message);
                const signature = sodium.crypto_sign_detached(messageUint8, this.#userKeys.privateKey.slice(1));
                const signatureHex = sodium.to_hex(signature);

                console.log('Sending the message...');
                this.#wsClient.send(JSON.stringify({
                    signature: signatureHex,
                    message: message
                }));
            }
            catch (e) {
                failure(e);
            }

        });
    }
}

module.exports = {
    LobbyManager
}