const HotPocket = require('hotpocket-js-client');

class CommonHelper {
    static async generateKeys(privateKey = null, format = 'hex') {
        const keys = await HotPocket.generateKeys(privateKey);
        return format === 'hex' ? {
            privateKey: Buffer.from(keys.privateKey).toString('hex'),
            publicKey: Buffer.from(keys.publicKey).toString('hex')
        } : keys;
    }
}

module.exports = {
    CommonHelper
}