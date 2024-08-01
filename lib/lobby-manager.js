
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

        // TODO: Comment rejectUnauthorized: false so the instance creation will be rejected if ssl certificate is invalid.
        const server = `wss://${this.#ip}:${this.#userPort}`;
        this.#wsClient = new WebSocket(server, {
            rejectUnauthorized: false
        });
    }

    terminate() {
        if (this.#wsClient)
            this.#wsClient.close()
    }

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
                case 'run':
                    if (msg.status === 'SUCCESS')
                        return true;
                    else
                        throw msg.data ?? 'UNKNOWN_ERROR';
                default:
                    throw 'UNHANDLED_MESSAGE';
            }
        }
    }

    async runContract(instanceDetails, timeoutMs = DEFAULT_TIMEOUT) {
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
                            success('CONTRACT_RAN');
                        else
                            throw 'UNKNOWN_ERROR'
                    }
                    catch (e) {
                        failure(e);
                    }
                });

                this.#wsClient.on('open', () => {
                    console.log('Connection opened. Sending run request...');
                    try {
                        console.log('Signing the message...');
                        const message = JSON.stringify({
                            type: 'run',
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
            catch (e) {
                failure(e);
            }

        });
    }

    async upgradeContract(unl, peers, timeoutMs = DEFAULT_TIMEOUT) {
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

                this.#wsClient.on('open', () => {
                    console.log('Connection opened. Sending upgrade request...');
                    try {
                        console.log('Signing the message...');
                        const message = JSON.stringify({
                            type: 'upgrade',
                            unl: unl,
                            peers: peers
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
            catch (e) {
                failure(e);
            }

        });
    }
}

module.exports = {
    LobbyManager
}