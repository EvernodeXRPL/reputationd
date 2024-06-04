const fs = require('fs');

const COMMON_CONFIG_KEYS = ['network', 'governorAddress', 'rippledServer'];

class ConfigHelper {
    static readConfig(configPath, mbXrplConfigPath = null, readSecret = false) {
        if (!fs.existsSync(configPath))
            throw `Config file does not exist at ${configPath}`;

        let config = JSON.parse(fs.readFileSync(configPath).toString());

        if (readSecret) {
            if (!fs.existsSync(config.xrpl.secretPath))
                throw `Secret config file does not exist at ${config.xrpl.secretPath}`;

            const secretCfg = JSON.parse(fs.readFileSync(config.xrpl.secretPath).toString());
            config.xrpl = { ...config.xrpl, ...secretCfg.xrpl };
        }

        if (mbXrplConfigPath && fs.existsSync(mbXrplConfigPath)) {
            let mbXrplConfig = JSON.parse(fs.readFileSync(mbXrplConfigPath).toString());

            if (readSecret) {
                if (!fs.existsSync(mbXrplConfig.xrpl.secretPath))
                    throw `Secret config file does not exist at ${mbXrplConfig.xrpl.secretPath}`;

                const mbXrplSecretCfg = JSON.parse(fs.readFileSync(mbXrplConfig.xrpl.secretPath).toString());
                mbXrplConfig.xrpl = { ...mbXrplConfig.xrpl, ...mbXrplSecretCfg.xrpl }
            }

            for (const e of Object.entries(mbXrplConfig.xrpl)) {
                const key = COMMON_CONFIG_KEYS.includes(e[0]) ? e[0] : `host${e[0].charAt(0).toUpperCase()}${e[0].slice(1)}`;
                if (!(key in config.xrpl))
                    config.xrpl[key] = e[1];
            }
        }

        return config;
    }

    static writeConfig(config, configPath) {
        let publicCfg = JSON.parse(JSON.stringify(config)); // Make a copy. So, referenced object won't get changed.
        if ('secret' in publicCfg.xrpl)
            delete publicCfg.xrpl.secret;
        if ('network' in publicCfg.xrpl)
            delete publicCfg.xrpl.network;
        if ('governorAddress' in publicCfg.xrpl)
            delete publicCfg.xrpl.governorAddress;
        if ('rippledServer' in publicCfg.xrpl)
            delete publicCfg.xrpl.rippledServer;
        // Remove host related props.
        for (const e of Object.entries(publicCfg.xrpl)) {
            if (e[0].startsWith('host'))
                delete publicCfg.xrpl[e[0]];
        }
        fs.writeFileSync(configPath, JSON.stringify(publicCfg, null, 2), { mode: 0o644 }); // Set file permission so only current user can read/write and others can read.
    }
}

module.exports = {
    ConfigHelper
}