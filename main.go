package main

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/fbsobreira/gotron-sdk/pkg/address"
	"github.com/gagliardetto/solana-go"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
	"github.com/xssnick/tonutils-go/ton/wallet"
)

type Wallet struct {
	Network    string
	Address    string
	PrivateKey string
	Mnemonic   string
}

func main() {
	fmt.Println("=== Master wallets generator ===")
	fmt.Println()

	// Tron
	tron, err := GenerateTron()
	if err != nil {
		log.Printf("Tron error: %v", err)
	} else {
		printWallet(tron)
	}

	// Ethereum
	eth, err := GenerateEthereum()
	if err != nil {
		log.Printf("Ethereum error: %v", err)
	} else {
		printWallet(eth)
	}

	// BSC
	bsc, err := GenerateBsc()
	if err != nil {
		log.Printf("BSC error: %v", err)
	} else {
		printWallet(bsc)
	}

	// TON
	ton, err := GenerateTon()
	if err != nil {
		log.Printf("TON error: %v", err)
	} else {
		printWallet(ton)
	}

	// Bitcoin
	btc, err := GenerateBitcoin()
	if err != nil {
		log.Printf("Bitcoin error: %v", err)
	} else {
		printWallet(btc)
	}

	// Solana
	sol, err := GenerateSolana()
	if err != nil {
		log.Printf("Solana error: %v", err)
	} else {
		printWallet(sol)
	}
}

// GenerateTron Generate Tron wallet using BIP44 path (m/44'/195'/0'/0/0)
func GenerateTron() (*Wallet, error) {
	// Generate mnemonic
	mnemonic, err := generateMnemonic()
	if err != nil {
		return nil, err
	}

	// BIP44 path: m/44'/195'/0'/0/0
	path := []uint32{
		bip32.FirstHardenedChild + 44,
		bip32.FirstHardenedChild + 195,
		bip32.FirstHardenedChild + 0,
		0,
		0,
	}
	// Derive child keys
	privateKeyBytes, err := deriveKey(mnemonic, path)
	if err != nil {
		return nil, err
	}

	// Get private key
	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return nil, err
	}
	// Get address
	addr := address.PubkeyToAddress(privateKey.PublicKey)

	return &Wallet{
		Network:    "Tron",
		Address:    addr.String(),
		PrivateKey: hex.EncodeToString(privateKeyBytes),
		Mnemonic:   mnemonic,
	}, nil
}

// GenerateEthereum Generate Ethereum wallet using BIP44 path (m/44'/60'/0'/0/0)
func GenerateEthereum() (*Wallet, error) {
	// Generate mnemonic
	mnemonic, err := generateMnemonic()
	if err != nil {
		return nil, err
	}

	// BIP44 path: m/44'/60'/0'/0/0
	path := []uint32{
		bip32.FirstHardenedChild + 44,
		bip32.FirstHardenedChild + 60,
		bip32.FirstHardenedChild + 0,
		0,
		0,
	}
	// Derive child keys
	privateKeyBytes, err := deriveKey(mnemonic, path)
	if err != nil {
		return nil, err
	}

	// Get private key
	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return nil, err
	}
	// Get address
	addr := crypto.PubkeyToAddress(privateKey.PublicKey)

	return &Wallet{
		Network:    "Ethereum",
		Address:    addr.Hex(),
		PrivateKey: hexutil.Encode(crypto.FromECDSA(privateKey)),
		Mnemonic:   mnemonic,
	}, nil
}

// GenerateBsc Generate BSC wallet using BIP44 path (m/44'/60'/0'/0/0)
func GenerateBsc() (*Wallet, error) {
	// Generate mnemonic
	mnemonic, err := generateMnemonic()
	if err != nil {
		return nil, err
	}

	// BIP44 path: m/44'/60'/0'/0/0
	path := []uint32{
		bip32.FirstHardenedChild + 44,
		bip32.FirstHardenedChild + 60,
		bip32.FirstHardenedChild + 0,
		0,
		0,
	}
	// Derive child keys
	privateKeyBytes, err := deriveKey(mnemonic, path)
	if err != nil {
		return nil, err
	}

	// Get private key
	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return nil, err
	}
	// Get address
	addr := crypto.PubkeyToAddress(privateKey.PublicKey)

	return &Wallet{
		Network:    "BSC",
		Address:    addr.Hex(),
		PrivateKey: hexutil.Encode(crypto.FromECDSA(privateKey)),
		Mnemonic:   mnemonic,
	}, nil
}

// GenerateTon Generate TON wallet using its native 24-word mnemonic
func GenerateTon() (*Wallet, error) {
	// Generate seed
	seed := wallet.NewSeed()

	// Get wallet from seed
	w, err := wallet.FromSeedWithOptions(nil, seed, wallet.V4R2)
	if err != nil {
		return nil, err
	}

	// Get wallet private key
	privateKey := w.PrivateKey()

	return &Wallet{
		Network:    "TON",
		Address:    w.WalletAddress().String(),
		PrivateKey: hex.EncodeToString(privateKey.Seed()),
		Mnemonic:   strings.Join(seed, " "),
	}, nil
}

// GenerateBitcoin Generate Bitcoin Native SegWit wallet using BIP84 path (m/84'/0'/0'/0/0)
func GenerateBitcoin() (*Wallet, error) {
	// Generate mnemonic
	mnemonic, err := generateMnemonic()
	if err != nil {
		return nil, err
	}

	// BIP84 for Native SegWit: m/84'/0'/0'/0/0
	path := []uint32{
		bip32.FirstHardenedChild + 84,
		bip32.FirstHardenedChild + 0,
		bip32.FirstHardenedChild + 0,
		0,
		0,
	}
	// Derive child keys
	privateKeyBytes, err := deriveKey(mnemonic, path)
	if err != nil {
		return nil, err
	}

	// Convert to btcec private key
	privateKey, _ := btcec.PrivKeyFromBytes(privateKeyBytes)

	// Get native SegWit address (bc1q...)
	pubKeyHash := btcutil.Hash160(privateKey.PubKey().SerializeCompressed())
	addr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
	if err != nil {
		return nil, err
	}

	// Get private key in WIF format
	wif, err := btcutil.NewWIF(privateKey, &chaincfg.MainNetParams, true)
	if err != nil {
		return nil, err
	}

	return &Wallet{
		Network:    "Bitcoin",
		Address:    addr.EncodeAddress(),
		PrivateKey: wif.String(),
		Mnemonic:   mnemonic,
	}, nil
}

// GenerateSolana Generate Solana wallet using BIP44 path (m/44'/501'/0'/0')
func GenerateSolana() (*Wallet, error) {
	// Generate mnemonic
	mnemonic, err := generateMnemonic()
	if err != nil {
		return nil, err
	}

	// BIP44 path: m/44'/501'/0'/0' (Solana uses hardened derivation)
	path := []uint32{
		bip32.FirstHardenedChild + 44,
		bip32.FirstHardenedChild + 501,
		bip32.FirstHardenedChild + 0,
		bip32.FirstHardenedChild + 0,
	}
	// Derive child keys (all hardened for Ed25519)
	privateKeyBytes, err := deriveEd25519Key(mnemonic, path)
	if err != nil {
		return nil, err
	}

	// Create Ed25519 keys
	privateKey := ed25519.NewKeyFromSeed(privateKeyBytes)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	// Create Solana address and private key (in base58)
	solanaPublicKey := solana.PublicKeyFromBytes(publicKey)
	solanaPrivKey := solana.PrivateKey(privateKey)

	return &Wallet{
		Network:    "Solana",
		Address:    solanaPublicKey.String(),
		PrivateKey: solanaPrivKey.String(),
		Mnemonic:   mnemonic,
	}, nil
}

// printWallet Prints wallet data in readable format
func printWallet(w *Wallet) {
	fmt.Printf("[%s]\n", w.Network)
	fmt.Printf("Address:     %s\n", w.Address)
	fmt.Printf("Private Key: %s\n", w.PrivateKey)
	if w.Mnemonic != "" {
		fmt.Printf("Mnemonic:    %s\n", w.Mnemonic)
	}
	fmt.Println()
}

// generateMnemonic Create new BIP39 mnemonic (12-word)
func generateMnemonic() (string, error) {
	entropy, err := bip39.NewEntropy(128) // 12 words
	if err != nil {
		return "", err
	}
	return bip39.NewMnemonic(entropy)
}

// deriveKey Derive private key from BIP44 path
func deriveKey(mnemonic string, path []uint32) ([]byte, error) {
	// Generate seed from mnemonic (BIP39)
	seed := bip39.NewSeed(mnemonic, "")

	// Create HD master key from seed
	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		return nil, err
	}

	// Derive child keys
	key := masterKey
	for _, idx := range path {
		key, err = key.NewChildKey(idx)
		if err != nil {
			return nil, err
		}
	}

	return key.Key, nil
}

// deriveEd25519Key Derive private key using SLIP-0010 for Ed25519 curves
func deriveEd25519Key(mnemonic string, path []uint32) ([]byte, error) {
	seed := bip39.NewSeed(mnemonic, "")

	// SLIP-0010: use "ed25519 seed" instead of "Bitcoin seed"
	mac := hmac.New(sha512.New, []byte("ed25519 seed"))
	mac.Write(seed)
	result := mac.Sum(nil)

	currentKey := result[:32]
	currentChainCode := result[32:]

	// Derive child keys (all must be hardened for Ed25519)
	for _, index := range path {
		data := make([]byte, 37)
		data[0] = 0x00
		copy(data[1:33], currentKey)
		binary.BigEndian.PutUint32(data[33:], index)

		h := hmac.New(sha512.New, currentChainCode)
		h.Write(data)
		result := h.Sum(nil)

		currentKey = result[:32]
		currentChainCode = result[32:]
	}

	return currentKey, nil
}
