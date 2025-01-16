require('dotenv').config();
const crypto = require('crypto');
const https = require('https');

// Exchange configurations
const EXCHANGES = {
    BINANCE: {
        name: 'Binance',
        hostname: 'api.binance.com',
        endpoints: {
            public: '/api/v3/time',
            private: '/api/v3/account'
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
            private: '/0/private/Balance'
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
            private: '/v2/accounts'
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
        this.timeout = 10000; // 10 second timeout
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

            // Add timeout
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
            timeout: this.timeout
        };

        return this.makeRequest(options);
    }

    async testPrivateEndpoint() {
        const timestamp = Date.now();
        const { options, postData } = this.getRequestConfig(timestamp);
        options.timeout = this.timeout;
        
        return this.makeRequest(options, postData);
    }

    getRequestConfig(timestamp) {
        try {
            switch(this.exchange.name) {
                case 'Binance': {
                    const queryString = `timestamp=${timestamp}`;
                    const signature = this.generateBinanceSignature(queryString);
                    
                    return {
                        options: {
                            hostname: this.exchange.hostname,
                            path: `${this.exchange.endpoints.private}?${queryString}&signature=${signature}`,
                            method: 'GET',
                            headers: {
                                'X-MBX-APIKEY': this.apiKey
                            }
                        }
                    };
                }
                
                case 'Kraken': {
                    const nonce = timestamp;
                    const path = this.exchange.endpoints.private;
                    const signature = this.generateKrakenSignature(path, nonce);
                    
                    return {
                        options: {
                            hostname: this.exchange.hostname,
                            path: path,
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
                    const path = this.exchange.endpoints.private;
                    const signature = this.generateCoinbaseSignature(timestamp, 'GET', path, '');
                    
                    return {
                        options: {
                            hostname: this.exchange.hostname,
                            path: path,
                            method: 'GET',
                            headers: {
                                'CB-ACCESS-KEY': this.apiKey,
                                'CB-ACCESS-SIGN': signature,
                                'CB-ACCESS-TIMESTAMP': timestamp,
                                'CB-VERSION': '2017-12-09'
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

    generateBinanceSignature(queryString) {
        try {
            return crypto
                .createHmac('sha256', this.apiSecret)
                .update(queryString)
                .digest('hex');
        } catch (error) {
            throw new Error(`Failed to generate Binance signature: ${error.message}`);
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
            case 'Binance':
                return response.code !== undefined;
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
                case 'Binance':
                    return response.msg || 'Unknown Binance error';
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

    getErrorDetails(error) {
        const errorMsg = error.message.toLowerCase();
        
        // Define common error patterns and their detailed explanations
        const errorPatterns = {
            'timeout': {
                title: `Connection timeout to ${this.exchange.name}`,
                reason: 'The server took too long to respond',
                solutions: [
                    'Check your internet connection',
                    'The exchange servers might be experiencing high load',
                    'Try again in a few minutes'
                ]
            },
            'connection error': {
                title: `Could not connect to ${this.exchange.name}`,
                reason: 'Unable to establish a connection to the exchange',
                solutions: [
                    'Verify your internet connection',
                    'Check if the exchange website is accessible in your browser',
                    'Your network might be blocking the connection'
                ]
            },
            'invalid key': {
                title: 'API key is not working',
                reason: 'The exchange rejected your API credentials',
                solutions: [
                    'Verify your API key and secret are copied correctly',
                    'Check if the API key is still active in your exchange account',
                    'Ensure the API key has the necessary permissions (read access)',
                    'Generate a new API key if the problem persists'
                ]
            },
            'permission denied': {
                title: 'Permission denied',
                reason: 'Your API key lacks the required permissions',
                solutions: [
                    'Check your API key permissions in your exchange account',
                    'Enable "read" or "query" permissions for the API key',
                    'You might need to generate a new API key with correct permissions'
                ]
            }
        };

        // Find matching error pattern
        let errorDetail = null;
        for (const [pattern, details] of Object.entries(errorPatterns)) {
            if (errorMsg.includes(pattern)) {
                errorDetail = details;
                break;
            }
        }

        // If no specific pattern found, provide a generic error
        if (!errorDetail) {
            errorDetail = {
                title: `Error: ${error.message}`,
                reason: 'An unexpected error occurred',
                solutions: [
                    'Check if your API credentials are correct',
                    'Verify the exchange is operational',
                    'Try again in a few minutes'
                ]
            };
        }

        return errorDetail;
    }

    async test() {
        console.log(`\n📡 Testing ${this.exchange.name} API...`);
        
        try {
            await this.testPublicEndpoint();
            console.log(`✅ Connected to ${this.exchange.name}`);
            
            await this.testPrivateEndpoint();
            console.log('✅ API key is working');
            return true;
        } catch (error) {
            const details = this.getErrorDetails(error);
            console.log(`❌ ${details.title}`);
            console.log(`  Reason: ${details.reason}`);
            console.log('  How to fix:');
            details.solutions.forEach(solution => {
                console.log(`    • ${solution}`);
            });
            return false;
        }
    }
}

async function testAllExchanges() {
    console.log('🔍 Detecting configured exchanges...\n');
    
    let foundAny = false;
    const results = [];

    // Test each exchange
    for (const exchange of Object.values(EXCHANGES)) {
        const tester = new ExchangeAPITester(exchange);
        
        if (tester.hasCredentials()) {
            foundAny = true;
            const success = await tester.test();
            results.push({ exchange: exchange.name, success });
        }
    }

    if (!foundAny) {
        console.log('❌ No API credentials found!');
        console.log('\nPlease add your credentials to .env file:');
        console.log('For Binance:');
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

    // Show summary
    console.log('\n📊 Summary:');
    results.forEach(({ exchange, success }) => {
        console.log(`${exchange}: ${success ? '✅ Working' : '❌ Not Working'}`);
    });
}

// Run all tests
testAllExchanges().catch(error => {
    console.error('❌ Fatal error:', error.message);
});