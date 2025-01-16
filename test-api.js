require('dotenv').config();
const crypto = require('crypto');
const https = require('https');

// Exchange configurations
const EXCHANGES = {
    TOKOCRYPTO: {
        name: 'Tokocrypto',
        hostname: 'www.tokocrypto.com',
        endpoints: {
            public: '/open/v1/common/time',
            private: '/open/v1/account/spot',
            trade: '/open/v1/orders/current'
        },
        envKeyNames: {
            apiKey: 'TOKOCRYPTO_API_KEY',
            apiSecret: 'TOKOCRYPTO_API_SECRET'
        }
    },
    BINANCE: {
        name: 'Binance',
        hostname: 'api.binance.com',
        endpoints: {
            public: '/api/v3/time',
            private: '/api/v3/account',
            trade: '/api/v3/openOrders'
        },
        envKeyNames: {
            apiKey: 'BINANCE_API_KEY',
            apiSecret: 'BINANCE_API_SECRET'
        }
    },
    KRAKEN: {
        name: 'Kraken',
        hostname: 'api.kraken.com',
        endpoints: {
            public: '/0/public/Time',
            private: '/0/private/Balance',
            trade: '/0/private/OpenOrders'
        },
        envKeyNames: {
            apiKey: 'KRAKEN_API_KEY',
            apiSecret: 'KRAKEN_API_SECRET'
        }
    },
    COINBASE: {
        name: 'Coinbase',
        hostname: 'api.coinbase.com',
        endpoints: {
            public: '/v2/time',
            private: '/v2/accounts',
            trade: '/v2/orders'
        },
        envKeyNames: {
            apiKey: 'COINBASE_API_KEY',
            apiSecret: 'COINBASE_API_SECRET'
        }
    }
};

class ExchangeAPITester {
    constructor(exchange) {
        this.exchange = exchange;
        this.apiKey = process.env[exchange.envKeyNames.apiKey];
        this.apiSecret = process.env[exchange.envKeyNames.apiSecret];
        this.timeout = 30000; // 30 second timeout
    }

    hasCredentials() {
        return !!(this.apiKey && this.apiSecret);
    }

    makeRequest(options, postData = null) {
        return new Promise((resolve, reject) => {
            const req = https.request(options, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    try {
                        const response = JSON.parse(data);
                        if (this.hasError(response)) {
                            reject(new Error(this.getErrorMessage(response)));
                        } else {
                            resolve(response);
                        }
                    } catch (error) {
                        reject(new Error(`Invalid response from ${this.exchange.name}`));
                    }
                });
            });

            req.on('error', (error) => {
                reject(new Error(`Connection error: ${error.message}`));
            });

            req.setTimeout(this.timeout, () => {
                req.destroy();
                reject(new Error(`Connection timeout to ${this.exchange.name}`));
            });

            if (postData) {
                req.write(postData);
            }
            req.end();
        });
    }

    async testPublicEndpoint() {
        const options = {
            hostname: this.exchange.hostname,
            path: this.exchange.endpoints.public,
            method: 'GET',
            timeout: this.timeout,
            headers: {
                'User-Agent': 'APITester/1.0',
                'Accept': 'application/json'
            }
        };

        return this.makeRequest(options);
    }

    async testPrivateEndpoint() {
        const timestamp = Date.now();
        const { options, postData } = this.getRequestConfig(timestamp, this.exchange.endpoints.private);
        options.timeout = this.timeout;
        
        return this.makeRequest(options, postData);
    }

    async testTradePermissions() {
        const timestamp = Date.now();
        const { options, postData } = this.getRequestConfig(timestamp, this.exchange.endpoints.trade);
        options.timeout = this.timeout;

        try {
            await this.makeRequest(options, postData);
            return true;
        } catch (error) {
            return false;
        }
    }

    getRequestConfig(timestamp, endpoint) {
        try {
            switch(this.exchange.name) {
                case 'Tokocrypto':
                case 'Binance': {
                    const queryString = `timestamp=${timestamp}`;
                    const signature = this.generateSignature(queryString);
                    
                    return {
                        options: {
                            hostname: this.exchange.hostname,
                            path: `${endpoint}?${queryString}&signature=${signature}`,
                            method: 'GET',
                            headers: {
                                'X-MBX-APIKEY': this.apiKey,
                                'Content-Type': 'application/json'
                            }
                        }
                    };
                }
                
                case 'Kraken': {
                    const nonce = timestamp;
                    const signature = this.generateKrakenSignature(endpoint, nonce);
                    
                    return {
                        options: {
                            hostname: this.exchange.hostname,
                            path: endpoint,
                            method: 'POST',
                            headers: {
                                'API-Key': this.apiKey,
                                'API-Sign': signature,
                                'Content-Type': 'application/x-www-form-urlencoded'
                            }
                        },
                        postData: `nonce=${nonce}`
                    };
                }

                case 'Coinbase': {
                    const timestamp = Math.floor(Date.now() / 1000);
                    const method = 'GET';
                    const signature = this.generateCoinbaseSignature(timestamp, method, endpoint, '');
                    
                    return {
                        options: {
                            hostname: this.exchange.hostname,
                            path: endpoint,
                            method: method,
                            headers: {
                                'CB-ACCESS-KEY': this.apiKey,
                                'CB-ACCESS-SIGN': signature,
                                'CB-ACCESS-TIMESTAMP': timestamp,
                                'CB-VERSION': '2021-04-29'
                            }
                        }
                    };
                }
                
                default:
                    throw new Error(`Unsupported exchange: ${this.exchange.name}`);
            }
        } catch (error) {
            throw new Error(`Failed to generate request configuration: ${error.message}`);
        }
    }

    generateSignature(queryString) {
        try {
            return crypto
                .createHmac('sha256', this.apiSecret)
                .update(queryString)
                .digest('hex');
        } catch (error) {
            throw new Error(`Failed to generate signature: ${error.message}`);
        }
    }

    generateKrakenSignature(path, nonce) {
        try {
            const message = nonce + 'nonce=' + nonce;
            const secret = Buffer.from(this.apiSecret, 'base64');
            const hash = crypto.createHash('sha256').update(message).digest();
            const hmac = crypto.createHmac('sha512', secret);
            return hmac.update(path + hash).digest('base64');
        } catch (error) {
            throw new Error(`Failed to generate Kraken signature: ${error.message}`);
        }
    }

    generateCoinbaseSignature(timestamp, method, path, body) {
        try {
            const message = timestamp + method + path + body;
            return crypto
                .createHmac('sha256', this.apiSecret)
                .update(message)
                .digest('hex');
        } catch (error) {
            throw new Error(`Failed to generate Coinbase signature: ${error.message}`);
        }
    }

    hasError(response) {
        switch(this.exchange.name) {
            case 'Tokocrypto':
            case 'Binance':
                return response.code !== 0;
            case 'Kraken':
                return response.error && response.error.length > 0;
            case 'Coinbase':
                return response.errors !== undefined;
            default:
                return false;
        }
    }

    getErrorMessage(response) {
        try {
            switch(this.exchange.name) {
                case 'Tokocrypto':
                case 'Binance':
                    return response.msg || `Unknown ${this.exchange.name} error`;
                case 'Kraken':
                    return response.error?.[0] || 'Unknown Kraken error';
                case 'Coinbase':
                    return response.errors?.[0]?.message || 'Unknown Coinbase error';
                default:
                    return 'Unknown error';
            }
        } catch (error) {
            return 'Failed to parse error message';
        }
    }

    async test() {
        try {
            // Test basic connectivity
            await this.testPublicEndpoint();
            await this.testPrivateEndpoint();
            
            // Test trading permissions
            const canTrade = await this.testTradePermissions();
            
            console.log(`✅ ${this.exchange.name}: API working${canTrade ? ' (Trading enabled)' : ' (Read-only)'}`);
            return true;
        } catch (error) {
            let errorMessage = `❌ ${this.exchange.name}: `;
            
            if (error.message.includes('Invalid response')) {
                errorMessage += 'API endpoint not accessible';
            } else if (error.message.includes('Invalid key')) {
                errorMessage += 'Invalid API key';
            } else if (error.message.includes('Permission denied')) {
                errorMessage += 'API key lacks required permissions';
            } else if (error.message.includes('timeout')) {
                errorMessage += 'Connection timeout';
            } else {
                errorMessage += error.message;
            }
            
            console.log(errorMessage);
            return false;
        }
    }
}

async function testAllExchanges() {
    console.log('\n🔐 Crypto Exchange API Tester');
    console.log('============================');
    
    let foundAny = false;
    const results = [];

    for (const exchange of Object.values(EXCHANGES)) {
        const tester = new ExchangeAPITester(exchange);
        
        if (tester.hasCredentials()) {
            foundAny = true;
            const success = await tester.test();
            results.push({ exchange: exchange.name, success });
        }
    }

    if (!foundAny) {
        console.log('\n❌ No API credentials found!');
        console.log('Add your credentials to .env file:');
        console.log('\nFor Tokocrypto:');
        console.log('  TOKOCRYPTO_API_KEY=your_key');
        console.log('  TOKOCRYPTO_API_SECRET=your_secret');
        console.log('\nFor Binance:');
        console.log('  BINANCE_API_KEY=your_key');
        console.log('  BINANCE_API_SECRET=your_secret');
        console.log('\nFor Kraken:');
        console.log('  KRAKEN_API_KEY=your_key');
        console.log('  KRAKEN_API_SECRET=your_secret');
        console.log('\nFor Coinbase:');
        console.log('  COINBASE_API_KEY=your_key');
        console.log('  COINBASE_API_SECRET=your_secret');
        return;
    }

    if (results.length > 1) {
        console.log('\n📊 Summary');
        console.log('===============');
        results.forEach(({ exchange, success }) => {
            console.log(`${exchange}: ${success ? '✅ Working' : '❌ Not Working'}`);
        });
    }
}

// Run the tests
testAllExchanges().catch(error => {
    console.error('\n❌ Fatal error:', error.message);
});