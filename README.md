# Master Wallet Generator

Wallet generator for blockchain networks with BIP39/BIP44 mnemonic support.

## Supported chains

| Chain    | BIP44 Path           | Address Type          |
|----------|----------------------|-----------------------|
| Ethereum | m/44'/60'/0'/0/0     | 0x...                 |
| BSC      | m/44'/60'/0'/0/0     | 0x...                 |
| Tron     | m/44'/195'/0'/0/0    | T...                  |
| Bitcoin  | m/84'/0'/0'/0/0      | bc1q... (Native SegWit) |
| Solana   | m/44'/501'/0'/0'     | Base58                |
| TON      | Own standard         | EQ.../UQ...           |

## Start
```bash
go mod tidy
go run main.go
```

## Output example
```
=== Master wallets generator ===

[Tron]
Address:     TXyz...
Private Key: abcd...
Mnemonic:    word1 word2 ... word12

[Ethereum]
Address:     0x1234...
Private Key: 0xabcd...
Mnemonic:    word1 word2 ... word12

[BSC]
Address:     0x5678...
Private Key: 0xefgh...
Mnemonic:    word1 word2 ... word12

[TON]
Address:     EQ...
Private Key: abcd...
Mnemonic:    word1 word2 ... word24

[Bitcoin]
Address:     bc1q...
Private Key: L5abc... (WIF)
Mnemonic:    word1 word2 ... word12

[Solana]
Address:     ABC123...
Private Key: xyz...
Mnemonic:    word1 word2 ... word12
```

## Notes

- All wallets generate 12-word BIP39 mnemonic (TON uses own 24-word standard)
- Compatible with popular wallets: MetaMask, Phantom, TronLink, Trust Wallet
- Bitcoin uses BIP84 for Native SegWit addresses
- Bitcoin private key exported in WIF format
- BSC uses same derivation path as Ethereum

## Security

⚠️ **Warning**: Never share your mnemonic phrases or private keys. Store them securely offline.