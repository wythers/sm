package tron

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcutil/base58"
	"github.com/fbsobreira/gotron-sdk/pkg/keys/hd"
	"github.com/shopspring/decimal"
	"github.com/tyler-smith/go-bip39"
)

// type Token struct {
// 	Symbol   string
// 	Address  string
// 	Decimals int
// }

// var (
// 	//	TokenABI = `[{"constant":true,"inputs":[{"name":"_owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],"type":"function"}]`
// 	BalanceFuncSelector string = "70a08231"
// 	// main net usdt contract address
// 	USDT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"

// 	TokenMap = map[string]*Token{
// 		USDT: {
// 			Symbol:   "usdt",
// 			Address:  USDT,
// 			Decimals: 6,
// 		},
// 	}

// 	TokenTransform = map[string]string{
// 		"usdt": USDT,
// 	}

// 	// transfer(address,uint256)
// //	TonkenTransferMethodID = crypto.Keccak256([]byte("transfer(address,uint256)"))[:4]
// // transferFrom(address,address,uint256)
// //	TonkenTransferFromMethodID = crypto.Keccak256([]byte("transferFrom(address,address,uint256)"))[:4]
// )

func SunToDecimal(amount *big.Int) decimal.Decimal {
	return decimal.NewFromBigInt(amount, -6)
}

func DecimalToSun(amount decimal.Decimal) *big.Int {
	sun := amount.Mul(decimal.New(1, 6))
	result := new(big.Int)
	result.SetString(sun.String(), 10)
	return result
}

func BigIntToDecimal(amount *big.Int, decimals int) decimal.Decimal {
	return decimal.NewFromBigInt(amount, int32(-decimals))
}

func DecimalToBigInt(amount decimal.Decimal, decimals int) *big.Int {
	bi := amount.Mul(decimal.New(1, int32(decimals)))
	result := new(big.Int)
	result.SetString(bi.String(), 10)
	return result
}

func GenerateMnemonic() (string, error) {
	entropy, err := bip39.NewEntropy(128)
	if err != nil {
		return "", fmt.Errorf("generate entropy failed: %v", err)
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", fmt.Errorf("generate mnemonic failed: %v", err)
	}

	return mnemonic, nil
}

func FromMnemonicSeedAndPassphrase(mnemonic, passphrase string, index int) (*btcec.PrivateKey, *btcec.PublicKey) {
	seed := bip39.NewSeed(mnemonic, passphrase)
	master, ch := hd.ComputeMastersFromSeed(seed, []byte("Bitcoin seed"))
	private, _ := hd.DerivePrivateKeyForPath(
		btcec.S256(),
		master,
		ch,
		fmt.Sprintf("44'/195'/0'/0/%d", index),
	)

	// p, _ := btcec.PrivKeyFromBytes(private[:])

	// pk_bytes := p.Serialize()

	return btcec.PrivKeyFromBytes(private[:])
}

func IsValidTronAddress(addr string) bool {
	if len(addr) == 0 {
		return false
	}
	decoded := base58.Decode(addr)
	if len(decoded) != 25 {
		return false
	}

	addressBytes := decoded[:len(decoded)-4]
	checksum := decoded[len(decoded)-4:]

	if addressBytes[0] != 0x41 {
		return false
	}

	if len(addressBytes[1:]) != 20 {
		return false
	}

	calculatedChecksum := S256(S256(addressBytes))[:4]
	return bytes.Equal(checksum, calculatedChecksum)
}

func S256(s []byte) []byte {
	h := sha256.New()
	h.Write(s)
	return h.Sum(nil)
}

func HexToBase58(hexStr string) string {
	hexStr = strings.TrimPrefix(hexStr, "0x")
	if hexStr == "" {
		return ""
	}

	if !strings.HasPrefix(hexStr, "41") {
		hexStr = "41" + hexStr
	}

	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return ""
	}

	h1 := S256(bytes)
	h2 := S256(h1)
	bytes = append(bytes, h2[:4]...)

	return base58.Encode(bytes)
}

func Base58ToHex(address string) string {
	decodedAddress := base58.Decode(address)
	dst := make([]byte, hex.EncodedLen(len(decodedAddress)))
	hex.Encode(dst, decodedAddress)
	dst = dst[:len(dst)-8]
	return string(dst)
}

func IsDupTransactionError(err error) bool {
	if err == nil {
		return false
	}

	return strings.Contains(err.Error(), "DUP_TRANSACTION_ERROR")
}
