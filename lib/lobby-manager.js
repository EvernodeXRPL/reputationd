
const { CommonHelper } = require('./util-helper');
const WebSocket = require('ws');

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
        var message = JSON.parse(message);
        switch (message.type) {
            case 'upgrade':
                if (message.status === 'SUCCESS')
                    return true;
                else
                    throw message.data ?? 'UNKNOWN_ERROR';
            default:
                throw 'UNHANDLED_MESSAGE';
        }
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
                        this.#wsClient.send(JSON.stringify({
                            type: 'upgrade',
                            user: this.#userKeys.publicKey,
                            data: {
                                unl: unl,
                                peers: peers
                            }
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