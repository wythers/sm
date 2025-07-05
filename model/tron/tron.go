package tron

import (
	"math/big"

	"github.com/shopspring/decimal"
)

type RawTransaction struct {
	Hash  string `json:"hash"`
	From  string `json:"from"`
	To    string `json:"to"`
	Value string `json:"value"`
	Input string `json:"input"`
}

type Block struct {
	Number         uint64         `json:"number"`
	Hash           string         `json:"hash"`
	ParentHash     string         `json:"parentHash"`
	Timestamp      uint64         `json:"timestamp"`
	Version        int            `json:"version"`
	TxTrieRoot     string         `json:"transactionsRoot"`
	Witness        string         `json:"miner"`
	TransactionNum int            `json:"transactionNum"`
	Transactions   []*Transaction `json:"transactions"`
}

type Transaction struct {
	TxID         string   `json:"txID"`
	From         string   `json:"from"`
	To           string   `json:"to"`
	AmountTrx    *big.Int `json:"amountTrx"`
	ContractType string   `json:"contractType"`
	ContractAddr string   `json:"contractAddr"`
	IsTrc20      bool     `json:"isTrc20"`
	Trc20Amount  *big.Int `json:"trc20Amount"`
}

const (
	ContractTypeTransfer     = "TransferContract"
	ContractTypeTriggerSmart = "TriggerSmartContract"
	TRC20TransferMethodID    = "a9059cbb"
)

type TransactionInfo struct {
	BlockNumber    int64 `json:"blockNumber"`
	BlockTimeStamp int64 `json:"blockTimeStamp"`
}

type BlockHeader struct {
	Number     uint64
	Hash       string
	ParentHash string
}

type Bill struct {
	Type string `json:"type"`
	//	Spender     string          `json:"spender,omitempty"`
	From        string          `json:"from"`
	To          string          `json:"to"`
	Amount      decimal.Decimal `json:"amount"`
	FromWatched bool            `json:"from_watched"`
	ToWatched   bool            `json:"to_watched"`
	Token       string          `json:"token"`
	GasFee      decimal.Decimal `json:"gas_fee,omitempty"`
	TxHash      string          `json:"tx_hash"`
	Msg         string          `json:"message"`
}

type BlockBills struct {
	BlockNumber uint64  `json:"block_number"`
	Bills       []*Bill `json:"bills"`
}

type BillKeeper interface {
	Write(bills *BlockBills) error
}

type PendingElement struct {
	Address string `json:"address"`
	Coin    string `json:"coin"`
}

type Raw struct {
	Visible    bool    `json:"visible"`
	TxID       string  `json:"txID"`
	RawData    RawData `json:"raw_data"`
	RawDataHex string  `json:"raw_data_hex"`
}

type SignedTx struct {
	Visible    bool     `json:"visible"`
	TxID       string   `json:"txID"`
	RawData    string   `json:"raw_data"`
	RawDataHex string   `json:"raw_data_hex"`
	Signature  []string `json:"signature,omitempty"`
}

type RawData struct {
	Contract []struct {
		Parameter struct {
			Value struct {
				Data            string `json:"data"`
				Amount          int    `json:"amount"`
				OwnerAddress    string `json:"owner_address"`
				ContractAddress string `json:"contract_address"`
				ToAddress       string `json:"to_address"`
				// FreezeBalanceV2Contract specific fields
				FrozenBalance int64  `json:"frozen_balance"`
				Resource      string `json:"resource"`
				// DelegateResourceContract and UnDelegateResourceContract specific fields
				Balance         int64  `json:"balance"`
				ReceiverAddress string `json:"receiver_address"`
			} `json:"value"`
			TypeURL string `json:"type_url"`
		} `json:"parameter"`
		Type string `json:"type"`
	} `json:"contract"`
	RefBlockBytes string `json:"ref_block_bytes"`
	RefBlockHash  string `json:"ref_block_hash"`
	Expiration    int64  `json:"expiration"`
	Timestamp     int64  `json:"timestamp"`
	FeeLimit      int64  `json:"fee_limit"`
}

type FreezeBalance2Request struct {
	OwnerAddress  string `json:"owner_address"`
	FrozenBalance int64  `json:"frozen_balance"`
	Resource      string `json:"resource"`
	Visible       bool   `json:"visible"`
}

type FreezeBalance2Response struct {
	Visible bool   `json:"visible"`
	TxID    string `json:"txID"`
	RawData struct {
		Contract []struct {
			Parameter struct {
				Value struct {
					Resource      string `json:"resource"`
					FrozenBalance int64  `json:"frozen_balance"`
					OwnerAddress  string `json:"owner_address"`
				} `json:"value"`
				TypeURL string `json:"type_url"`
			} `json:"parameter"`
			Type string `json:"type"`
		} `json:"contract"`
		RefBlockBytes string `json:"ref_block_bytes"`
		RefBlockHash  string `json:"ref_block_hash"`
		Expiration    int64  `json:"expiration"`
		Timestamp     int64  `json:"timestamp"`
	} `json:"raw_data"`
	RawDataHex string `json:"raw_data_hex"`
}

type DelegatedResourceAccountIndex struct {
	Account      string   `json:"account"`
	FromAccounts []string `json:"fromAccounts"`
	ToAccounts   []string `json:"toAccounts"`
}

type AssetNetInfo struct {
	Key   string `json:"key"`
	Value int64  `json:"value"`
}

type AccountResource struct {
	FreeNetUsed  int64 `json:"freeNetUsed"`
	FreeNetLimit int64 `json:"freeNetLimit"`
	//	AssetNetUsed      []AssetNetInfo `json:"assetNetUsed"`
	//	AssetNetLimit     []AssetNetInfo `json:"assetNetLimit"`
	TotalNetLimit     int64 `json:"TotalNetLimit"`
	TotalNetWeight    int64 `json:"TotalNetWeight"`
	TronPowerLimit    int64 `json:"tronPowerLimit"`
	EnergyUsed        int64 `json:"EnergyUsed"`
	EnergyLimit       int64 `json:"EnergyLimit"`
	TotalEnergyLimit  int64 `json:"TotalEnergyLimit"`
	TotalEnergyWeight int64 `json:"TotalEnergyWeight"`
}

type WithdrawRewardResponse struct {
	Result bool `json:"result"`
}

type RewardInfo struct {
	RewardAmount int64 `json:"reward"`
}
