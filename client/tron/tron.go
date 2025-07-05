package tron

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/shopspring/decimal"
	model "github.com/wythers/sm/model/tron"
	util "github.com/wythers/sm/util/tron"
)

var ErrNotSynced = errors.New("transaction not synced to solidity node")
var ErrTransactionFailed = errors.New("transaction failed")
var ErrTokenNotFound = errors.New("token not found")
var ErrGetEnergyFailed = errors.New("get energy failed")
var ErrInsufficientEnergy = errors.New("insufficient energy")

type clean = func(string, string, int64, string)

func nothing(_ string, _ string, _ int64, _ string) {}

type Client struct {
	http.Client

	Ctx context.Context

	Url string
}

func NewClient(ctx context.Context, url string) *Client {
	return &Client{
		Client: http.Client{},
		Ctx:    ctx,
		Url:    url,
	}
}

func (c *Client) GetTRC20Balance(address string, contractAddr string, decimals int) (decimal.Decimal, error) {
	balance := decimal.Zero

	data := `
	{
		"id":      1,
		"jsonrpc": "2.0",
		"method":  "eth_call",
		"params": [
			{
				"to":    "0x` + util.Base58ToHex(contractAddr)[2:] + `",
				"value": "0x0",
				"data":  "0x` + "70a08231" + strings.Repeat("0", 24) + util.Base58ToHex(address)[2:] + `"
			},
			"latest"
		]
	}`

	response, status, err := c.jsonRPC(
		[]byte(data),
		c.Url+"/jsonrpc",
		"POST",
	)

	if err != nil {
		return balance, err
	}
	if status != 200 {
		return balance, fmt.Errorf("getTRC20Balance status: %d,  body: %s", status, string(response))
	}

	var result struct {
		ID      any    `json:"id"`
		JSONRPC string `json:"jsonrpc"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error,omitempty"`
		Result string `json:"result,omitempty"`
	}
	err = json.Unmarshal(response, &result)
	if err != nil {
		return balance, err
	}
	if result.Result == "" {
		return balance, errors.New(string(response))
	}

	i := new(big.Int)
	i.SetString(result.Result[2:], 16)
	//
	balance = util.BigIntToDecimal(i, decimals)
	return balance, nil
}

func (c *Client) GetTRXBalance(address string) (decimal.Decimal, error) {

	data := `{
			"id":      1,
			"jsonrpc": "2.0",
			"method":  "eth_getBalance",
			"params":  ["0x` + util.Base58ToHex(address) + `", "latest"]
	}`

	response, status, err := c.jsonRPC(
		[]byte(data),
		c.Url+"/jsonrpc",
		"POST",
	)

	if err != nil {
		return decimal.Zero, err
	}
	if status != 200 {
		return decimal.Zero, fmt.Errorf("GetTRXBalance status: %d,  body: %s", status, string(response))
	}

	type Result struct {
		Jsonrpc string `json:"jsonrpc"`
		ID      any    `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error,omitempty"`
		Result string `json:"result,omitempty"`
	}
	result := Result{}
	err = json.Unmarshal(response, &result)
	if err != nil {
		return decimal.Zero, err
	}
	if result.Error.Code != 0 || result.Error.Message != "" {
		return decimal.Zero, errors.New(result.Error.Message)
	}
	if len(result.Result) < 3 {
		return decimal.Zero, errors.New("unexpected response")
	}

	if len(result.Result) <= 2 {
		return decimal.Zero, errors.New("balance value not found")
	}
	i := new(big.Int)
	i.SetString(result.Result[2:], 16)

	trx := util.SunToDecimal(i)
	return trx, nil
}

// func (c *Client) GetAllBalances(address string, tokenPairs map[string]int) (map[string]decimal.Decimal, error) {
// 	balances := make(map[string]decimal.Decimal)

// 	trx, err := c.GetTRXBalance(address)
// 	if err != nil {
// 		return nil, err
// 	}
// 	balances["trx"] = trx

// 	for key, decimals := range tokenPairs {
// 		balance, err := c.GetTRC20Balance(context.Background(), address, key, decimals)
// 		if err != nil {
// 			return nil, err
// 		}
// 		balances[key] = balance
// 	}
// 	return balances, nil
// }

func (c *Client) SignRawTransaction(tx *model.Raw, key *ecdsa.PrivateKey) (*model.SignedTx, error) {
	rawData, err := json.Marshal(tx.RawData)
	if err != nil {
		return nil, err
	}

	signedTx := &model.SignedTx{
		Visible:    tx.Visible,
		TxID:       tx.TxID,
		RawData:    string(rawData),
		RawDataHex: tx.RawDataHex,
	}
	txIDbytes, err := hex.DecodeString(tx.TxID)
	if err != nil {
		return nil, err
	}

	signature, err := crypto.Sign(txIDbytes, key)
	if err != nil {
		return nil, err
	}

	signedTx.Signature = append(signedTx.Signature, hex.EncodeToString(signature))
	return signedTx, nil
}

func (c *Client) BroadcastTransaction(tx *model.SignedTx) (string, error) {
	js, err := json.Marshal(tx)
	if err != nil {
		return "", err
	}
	response, status, err := c.jsonRPC(js, c.Url+"/wallet/broadcasttransaction", "POST")

	if err != nil {
		return "", err
	}
	if status != 200 {
		return "", fmt.Errorf("broadcastTransaction status: %d,  body: %s", status, string(response))
	}

	var result struct {
		Result bool
		Txid   string
	}
	err = json.Unmarshal(response, &result)
	if err != nil {
		return "", err
	}
	if !result.Result || result.Txid == "" {
		return "", fmt.Errorf("broadcastTransaction response: %s", string(response))
	}

	return result.Txid, nil
}

func (c *Client) Master(txID string) (*model.TransactionInfo, error) {
	data := fmt.Sprintf(`{"value": "%s"}`, txID)

	response, status, err := c.jsonRPC([]byte(data), c.Url+"/wallet/gettransactioninfobyid", "POST")

	if err != nil {
		return nil, fmt.Errorf("failed to get transaction info: %w", err)
	}
	if status != 200 {
		return nil, fmt.Errorf("get transaction info status: %d, body: %s", status, string(response))
	}

	var result model.TransactionInfo
	if err := json.Unmarshal(response, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (c *Client) FreezeBalance2WithKey(ownerAddress string, frozenBalance int64, resource string, privateKeyHex string) (string, error) {
	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return "", fmt.Errorf("failed to convert private key: %v", err)
	}

	jsonStr := fmt.Sprintf(`{
		"owner_address": "%s",
		"frozen_balance": %d,
		"resource": "%s",
		"visible": true
	}`, ownerAddress, frozenBalance, resource)
	data := []byte(jsonStr)

	body, statusCode, err := c.jsonRPC(data, c.Url+"/wallet/freezebalancev2", "POST")
	if err != nil {
		return "", fmt.Errorf("request failed: %v", err)
	}

	if statusCode != http.StatusOK {
		return "", fmt.Errorf("API request failed with status code: %d, body: %s", statusCode, string(body))
	}

	var raw model.Raw
	if err := json.Unmarshal(body, &raw); err != nil {
		return "", fmt.Errorf("failed to parse response: %v", err)
	}

	if raw.TxID == "" {
		return "", fmt.Errorf("freezebalancev2 API response has empty TxID, response: %s", string(body))
	}

	signedTx, err := c.SignRawTransaction(&raw, privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign transaction: %v", err)
	}

	txID, err := c.BroadcastTransaction(signedTx)
	if err != nil {
		return "", fmt.Errorf("failed to broadcast transaction: %v", err)
	}

	return txID, nil
}

func (c *Client) DelegateResourceWithKey(ownerAddress string, receiverAddress string, balance int64, resource string, privateKeyHex string) (string, error) {
	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return "", fmt.Errorf("failed to convert private key: %v", err)
	}

	jsonStr := fmt.Sprintf(`{
		"owner_address": "%s",
		"receiver_address": "%s",
		"balance": %d,
		"resource": "%s",
		"lock": false,
		"visible": true
	}`, ownerAddress, receiverAddress, balance, resource)
	data := []byte(jsonStr)

	body, statusCode, err := c.jsonRPC(data, c.Url+"/wallet/delegateresource", "POST")
	if err != nil {
		return "", fmt.Errorf("request failed: %v", err)
	}

	if statusCode != http.StatusOK {
		return "", fmt.Errorf("API request failed with status code: %d, body: %s", statusCode, string(body))
	}

	// fmt.Printf("DelegateResourceWithKey Response: %s\n", string(body))

	var raw model.Raw
	if err := json.Unmarshal(body, &raw); err != nil {
		return "", fmt.Errorf("failed to parse response: %v", err)
	}

	if raw.TxID == "" {
		return "", fmt.Errorf("delegateresource API response has empty TxID, response: %s", string(body))
	}

	signedTx, err := c.SignRawTransaction(&raw, privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign transaction: %v", err)
	}

	txID, err := c.BroadcastTransaction(signedTx)
	if err != nil {
		return "", fmt.Errorf("failed to broadcast transaction: %v", err)
	}

	return txID, nil
}

func (c *Client) GetDelegatedResourceAccountIndex(ownerAddress string) (*model.DelegatedResourceAccountIndex, error) {
	jsonStr := fmt.Sprintf(`{
		"value": "%s",
		"visible": true
	}`, ownerAddress)
	data := []byte(jsonStr)

	body, statusCode, err := c.jsonRPC(data, c.Url+"/walletsolidity/getdelegatedresourceaccountindexv2", "POST")
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}

	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status code: %d, body: %s", statusCode, string(body))
	}

	// fmt.Printf("GetDelegatedResourceAccountIndex Response: %s\n", string(body))

	var result model.DelegatedResourceAccountIndex
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v, body: %s", err, string(body))
	}

	return &result, nil
}

func (c *Client) UndelegateResourceWithKey(ownerAddress string, receiverAddress string, balance int64, resource string, privateKeyHex string) (string, error) {
	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return "", fmt.Errorf("failed to convert private key: %v", err)
	}

	jsonStr := fmt.Sprintf(`{
		"owner_address": "%s",
		"receiver_address": "%s",
		"balance": %d,
		"resource": "%s",
		"visible": true
	}`, ownerAddress, receiverAddress, balance, resource)
	data := []byte(jsonStr)

	body, statusCode, err := c.jsonRPC(data, c.Url+"/wallet/undelegateresource", "POST")
	if err != nil {
		return "", fmt.Errorf("request failed: %v", err)
	}

	if statusCode != http.StatusOK {
		return "", fmt.Errorf("API request failed with status code: %d, body: %s", statusCode, string(body))
	}

	// fmt.Printf("UndelegateResourceWithKey Response: %s\n", string(body))

	var raw model.Raw
	if err := json.Unmarshal(body, &raw); err != nil {
		return "", fmt.Errorf("failed to parse response: %v", err)
	}

	if raw.TxID == "" {
		return "", fmt.Errorf("undelegateresource API response has empty TxID, response: %s", string(body))
	}

	signedTx, err := c.SignRawTransaction(&raw, privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign transaction: %v", err)
	}

	txID, err := c.BroadcastTransaction(signedTx)
	if err != nil {
		return "", fmt.Errorf("failed to broadcast transaction: %v", err)
	}

	return txID, nil
}

// func (c *Client) GetAccount(ctx context.Context, address string) (*Account, error) {
// 	jsonStr := fmt.Sprintf(`{
// 		"address": "%s",
// 		"visible": true
// 	}`, address)
// 	data := []byte(jsonStr)

// 	_ = Rpc.Wait(ctx)
// 	body, statusCode, err := c.jsonRPC(data, c.Url+"/walletsolidity/getaccount", "POST")
// 	if err != nil {
// 		return nil, fmt.Errorf("request failed: %v", err)
// 	}

// 	if statusCode != http.StatusOK {
// 		return nil, fmt.Errorf("API request failed with status code: %d, body: %s", statusCode, string(body))
// 	}

// 	var account Account
// 	if err := json.Unmarshal(body, &account); err != nil {
// 		return nil, fmt.Errorf("failed to parse response: %v, body: %s", err, string(body))
// 	}

// 	return &account, nil
// }

func (c *Client) GetAccountResource(address string) (*model.AccountResource, error) {
	jsonStr := fmt.Sprintf(`{
		"address": "%s",
		"visible": true
	}`, address)
	data := []byte(jsonStr)

	body, statusCode, err := c.jsonRPC(data, c.Url+"/wallet/getaccountresource", "POST")
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}

	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status code: %d, body: %s", statusCode, string(body))
	}

	// fmt.Printf("GetAccountResource Response: %s\n", string(body))

	var resource model.AccountResource
	if err := json.Unmarshal(body, &resource); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v, body: %s", err, string(body))
	}

	return &resource, nil
}

func (c *Client) CheckE(txHash string) error {
	maxRetries := 30
	retryInterval := 10 * time.Second

	jsonStr := fmt.Sprintf(`{"value": "%s", "visible": true}`, txHash)

	var (
		stage1 = false
		stage2 = false
	)

	for i := 0; i < maxRetries; i++ {
		data := []byte(jsonStr)

		body, statusCode, err := c.jsonRPC(data, c.Url+"/wallet/gettransactionbyid", "POST")
		if err != nil || statusCode != http.StatusOK || strings.TrimSpace(string(body)) == "{}" {
			time.Sleep(retryInterval)
			continue
		}

		stage1 = true
	}

	if !stage1 {
		return ErrGetEnergyFailed
	}

	for i := 0; i < maxRetries; i++ {
		data := []byte(jsonStr)

		body, statusCode, err := c.jsonRPC(data, c.Url+"/walletsolidity/gettransactionbyid", "POST")
		if err != nil || statusCode != http.StatusOK || strings.TrimSpace(string(body)) == "{}" {
			time.Sleep(retryInterval)
			continue
		}

		type TxResult struct {
			Ret []struct {
				ContractRet string `json:"contractRet"`
			} `json:"ret"`
		}

		var solidTx TxResult

		if err := json.Unmarshal(body, &solidTx); err != nil {
			return fmt.Errorf("failed to parse solidity transaction: %v", err)
		}

		if len(solidTx.Ret) == 0 {
			time.Sleep(retryInterval)
			continue
		}

		if solidTx.Ret[0].ContractRet != "SUCCESS" {
			return fmt.Errorf("transaction failed with result: %s", solidTx.Ret[0].ContractRet)
		}

		stage2 = true
	}

	if !stage2 {
		return ErrGetEnergyFailed
	}

	return nil
}

func (c *Client) LockEnergy(owner, receiver string, balance int64, privateKeyHex string) (clean, int64, error) {
	idx, err := c.GetDelegatedResourceAccountIndex(owner)
	if err != nil {
		return nothing, 0, errors.New("get delegated resource account index failed")
	}

	for _, toAccount := range idx.ToAccounts {
		txID, err := c.UndelegateResourceWithKey(owner, toAccount, balance, "ENERGY", privateKeyHex)
		if err != nil {
			return nothing, 0, errors.New("undelegate resource failed: " + err.Error())
		}

		err = c.CheckE(txID)
		if err != nil {
			return nothing, 0, errors.New("failed verify undelegate resource transaction: " + err.Error())
		}
	}

	res, err := c.GetAccountResource(owner)
	if err != nil {
		return nothing, 0, errors.New("get account resource failed: " + err.Error())
	}

	//	en := decimal.NewFromInt(e.B).Mul(decimal.NewFromInt(10))
	cur := decimal.NewFromInt(res.EnergyLimit).Sub(decimal.NewFromInt(res.EnergyUsed))
	base := decimal.NewFromInt(res.TotalEnergyLimit)
	denominator := decimal.NewFromInt(res.TotalEnergyWeight)

	s := cur.Div(base).Mul(denominator).Round(0).Mul(decimal.NewFromInt(1000000))

	if s.LessThan(decimal.NewFromInt(balance)) {
		return nothing, 0, ErrInsufficientEnergy
	}

	cnt := s.Div(decimal.NewFromInt(balance)).Floor().IntPart()

	//	panic("now: " + now + " cnt: " + cnt.String() + " s: " + s.String() + " e.B: " + strconv.FormatInt(e.B, 10))

	txID, err := c.DelegateResourceWithKey(owner, receiver, balance, "ENERGY", privateKeyHex)
	if err != nil {
		return nothing, 0, errors.New("delegate resource failed: " + err.Error())
	}

	err = c.CheckE(txID)
	if err != nil {
		return nothing, 0, errors.New("faied verify delegate resource transaction: " + err.Error())
	}

	return c.UnlockEnergy, cnt - 1, nil
}

func (c *Client) UnlockEnergy(owner, receiver string, balance int64, privateKeyHex string) {
	txID, err := c.UndelegateResourceWithKey(owner, receiver, balance, "ENERGY", privateKeyHex)
	if err != nil {
		return
	}

	_ = c.CheckE(txID)
}

func (c *Client) RawTrxTransaction(from, to string, amount decimal.Decimal) (*model.Raw, string, error) {
	if !util.IsValidTronAddress(to) {
		return nil, "", errors.New("invalid tron to address")
	}

	var rawTransaction model.Raw
	amt := util.DecimalToBigInt(amount, 6)

	data := []byte(
		`{
				"owner_address": "` + from + `",
				"to_address": "` + to + `",
				"amount": ` + amt.String() + `,
				"visible": true
			  }`,
	)

	response, status, err := c.jsonRPC(
		data,
		c.Url+"/wallet/createtransaction",
		"POST",
	)

	if err != nil {
		return nil, "", err
	}
	if status != 200 {
		return nil, "", fmt.Errorf("createTransaction status: %d,  body: %s", status, string(response))
	}
	err = json.Unmarshal(response, &rawTransaction)
	if err != nil {
		return nil, "", err
	}
	if rawTransaction.TxID == "" {
		return nil, "", errors.New(string(response))
	}

	return &rawTransaction, string(response), nil
}

func (c *Client) RawTrc20Transaction(from, to string, contractAddress string, amount decimal.Decimal, decimals int) (*model.Raw, string, error) {
	if !util.IsValidTronAddress(to) || !util.IsValidTronAddress(contractAddress) {
		return nil, "", errors.New("invalid tron to address")
	}

	// token, ok := TokenMap[TokenTransform[strings.ToLower(tokenSymbol)]]
	// if !ok {
	// 	return nil, "", errors.New("token not supported")
	// }

	// if trxBalance.LessThan(requiredGasFee) {
	// 	return nil, "", fmt.Errorf("insufficient TRX for transaction fee: have %s, need %s", trxBalance.String(), requiredGasFee.String())
	// }

	denomination := decimal.New(1, int32(decimals))
	value := fmt.Sprintf("%x", amount.Mul(denomination).IntPart())

	payload := `
	{
		"owner_address": "` + util.Base58ToHex(from) + `",
		"contract_address": "` + util.Base58ToHex(contractAddress) + `", 
		"function_selector":"transfer(address,uint256)",
		"parameter":"` + strings.Repeat("0", 24) + util.Base58ToHex(to)[2:] + strings.Repeat("0", 64-len(value)) + value + `",
		"call_value":0,
		"fee_limit":10000000000
	}`

	response, status, err := c.jsonRPC(
		[]byte(payload),
		c.Url+"/wallet/triggersmartcontract",
		"POST",
	)
	if err != nil {
		return nil, "", err
	}
	if status != 200 {
		return nil, "", fmt.Errorf("triggersmartcontract status: %d, body: %s", status, string(response))
	}

	var result struct {
		Transaction model.Raw
	}
	err = json.Unmarshal(response, &result)
	if err != nil {
		return nil, "", err
	}

	if result.Transaction.TxID == "" {
		return nil, "", fmt.Errorf("triggersmartcontract response: %s", string(response))
	}

	result.Transaction.Visible = false

	rawJSON, err := json.Marshal(result.Transaction)
	if err != nil {
		return nil, "", err
	}

	return &result.Transaction, string(rawJSON), nil
}

func (c *Client) jsonRPC(data []byte, url, requestType string) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(c.Ctx, 8*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, requestType, url, bytes.NewBuffer(data))
	if err != nil {
		return nil, 0, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("accept", "application/json")

	resp, err := c.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}

	return body, resp.StatusCode, nil
}
