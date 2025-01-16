# Crypto Exchange API Tester 🚀

A simple tool to verify API connectivity and trading permissions for major cryptocurrency exchanges.

## Features ✨

- Automatic exchange detection from configured credentials
- Comprehensive API validation:
  - Public endpoint connectivity
  - Private endpoint authentication
  - Trading permission verification
- Clean, concise output with specific error messages
- Support for multiple exchanges:
  - Binance
  - Kraken
  - Coinbase
  - Tokocrypto

## Prerequisites 📋

Before using this tool, ensure you have:
- Node.js installed (version 12 or higher)
- Valid API credentials from any supported exchange

## Installation 🔧

1. Clone the repository:
```bash
git clone <repository-url>
cd crypto-api-tester
```

2. Install dependencies:
```bash
npm install
```

3. Create your environment file:
```bash
touch .env
```

4. Configure your API credentials in the `.env` file:
```env
# Tokocrypto credentials
TOKOCRYPTO_API_KEY=your_key_here
TOKOCRYPTO_API_SECRET=your_secret_here

# Binance credentials
BINANCE_API_KEY=your_key_here
BINANCE_API_SECRET=your_secret_here

# Kraken credentials
KRAKEN_API_KEY=your_key_here
KRAKEN_API_SECRET=your_secret_here

# Coinbase credentials
COINBASE_API_KEY=your_key_here
COINBASE_API_SECRET=your_secret_here
```

Note: You only need to add credentials for the exchanges you want to test.

## Usage 🎯

Run the tester:
```bash
node test-api.js
```

The tool will automatically detect and test all exchanges for which you have configured credentials.

### Example Outputs

Successful tests:
```
🔐 Crypto Exchange API Tester
============================
✅ Tokocrypto: API working (Trading enabled)
✅ Binance: API working (Trading enabled)
✅ Kraken: API working (Read-only)
```

Failed test:
```
🔐 Crypto Exchange API Tester
============================
✅ Tokocrypto: API working (Trading enabled)
❌ Binance: Invalid API key
❌ Kraken: Connection timeout
```

## Understanding Results 📊

The tool performs three levels of verification for each exchange:
1. Public API connectivity
2. Private API authentication
3. Trading permission validation

Status indicators:
- `API working (Trading enabled)`: Full access with trading capabilities
- `API working (Read-only)`: Basic access without trading permissions
- Error messages indicate specific issues with detailed reasons

## Security Notes 🔒

- Use read-only API keys for initial testing
- Never share your API credentials
- Keep your .env file secure and excluded from version control
- Regularly rotate your API keys
- Test trading features with small amounts first

## Troubleshooting 🔍

Common issues and solutions:

1. **Connection Timeout**
   - Check your internet connection
   - Verify if the exchange is accessible
   - Try again in a few minutes

2. **Invalid API Key**
   - Double-check credentials are copied correctly
   - Verify if the key is still active
   - Check if the key hasn't expired

3. **Permission Denied**
   - Review API key permissions in your exchange account
   - Ensure necessary access levels are enabled
   - Consider generating a new key with correct permissions

4. **No Trading Permission**
   - Verify trading is enabled for your API key
   - Check if your account has trading privileges
   - Confirm API key has required trading permissions

## Limitations ⚠️

This tool verifies API connectivity and permissions but does not guarantee:
- Order execution capability
- Market liquidity
- Fee levels
- Server stability during high volatility
- Rate limit availability

## Contributing 🤝

Contributions are welcome! You can:
- Report issues
- Suggest improvements
- Add support for additional exchanges
- Submit pull requests

## License 📄

This project is open source under the MIT License.

---

Questions or issues? Open an issue in the repository! 💡