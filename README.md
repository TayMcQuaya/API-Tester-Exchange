# Crypto Exchange API Tester 🚀

A simple tool to test your API connections with major cryptocurrency exchanges (Binance, Kraken, and Coinbase).

## Features ✨

- Automatically detects configured exchanges
- Tests both public and private API endpoints
- Provides detailed error messages and solutions
- Supports multiple exchanges:
  - Binance
  - Kraken
  - Coinbase

## Prerequisites 📋

Before you begin, make sure you have:
- Node.js installed (version 12 or higher)
- API credentials from any of the supported exchanges

## Installation 🔧

1. Clone or download this repository:
```bash
git clone <repository-url>
cd crypto-api-tester
```

2. Install dependencies:
```bash
npm install
```

3. Create a `.env` file in the project root:
```bash
touch .env
```

4. Add your API credentials to the `.env` file:
```env
# Binance credentials (if you have them)
BINANCE_API_KEY=your_binance_key
BINANCE_API_SECRET=your_binance_secret

# Kraken credentials (if you have them)
KRAKEN_API_KEY=your_kraken_key
KRAKEN_API_SECRET=your_kraken_secret

# Coinbase credentials (if you have them)
COINBASE_API_KEY=your_coinbase_key
COINBASE_API_SECRET=your_coinbase_secret
```

## Usage 🎯

Run the tester:
```bash
node test-api.js
```

The script will automatically detect which exchange credentials you've configured and test them.

### Example Output

Successful test:
```
🔍 Detecting configured exchanges...

📡 Testing Kraken API...
✅ Connected to Kraken
✅ API key is working

📊 Summary:
Kraken: ✅ Working
```

Failed test with helpful message:
```
🔍 Detecting configured exchanges...

📡 Testing Kraken API...
❌ API key is not working
  Reason: The exchange rejected your API credentials
  How to fix:
    • Verify your API key and secret are copied correctly
    • Check if the API key is still active in your exchange account
    • Ensure the API key has the necessary permissions (read access)
    • Generate a new API key if the problem persists

📊 Summary:
Kraken: ❌ Not Working
```

## Troubleshooting 🔍

### Common Issues

1. **No API credentials found**
   - Make sure your `.env` file exists and contains the correct API credentials
   - Check that the variable names match exactly (e.g., `KRAKEN_API_KEY`)

2. **Connection timeout**
   - Check your internet connection
   - Verify that the exchange's API servers are operational
   - Try running the test again

3. **Invalid API key**
   - Verify your API credentials are copied correctly
   - Check if the API key is still active in your exchange account
   - Ensure the API key has the necessary permissions

4. **Permission denied**
   - Check your API key permissions in your exchange account
   - Make sure the key has at least "read" or "query" access

## Security Notes 🔒

- Never share your API credentials
- Use API keys with read-only permissions for testing
- Don't commit your `.env` file to version control
- Regularly rotate your API keys

## Contributing 🤝

Found a bug or want to add support for another exchange? Feel free to:
1. Open an issue
2. Submit a pull request
3. Suggest improvements

## License 📄

This project is open source and available under the MIT License.

---

Need help? Open an issue in the repository! 💡