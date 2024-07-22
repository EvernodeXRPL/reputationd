const os = require('os');
const HotPocket = require('hotpocket-js-client');

class CommonHelper {
    static async generateKeys(privateKey = null, format = 'hex') {
        const keys = await HotPocket.generateKeys(privateKey);
        return format === 'hex' ? {
            privateKey: Buffer.from(keys.privateKey).toString('hex'),
            publicKey: Buffer.from(keys.publicKey).toString('hex')
        } : keys;
    }

    static hasIPv4() {
        const interfaces = os.networkInterfaces();
        return !!Object.values(interfaces).find(i => i.find(addr => addr.family === 'IPv4' && !addr.internal))
    }
}

module.exports = {
    CommonHelper
}