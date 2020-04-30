package energi

import (
	"blockbook/bchain"
	"bytes"
	"context"
	"encoding/hex"
	"math/big"
	"strings"
	"sync"
	"unicode/utf8"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/golang/glog"
	"github.com/juju/errors"
)

// doing the parsing/processing without using go-ethereum/accounts/abi library, it is simple to get data from Transfer event
const erc20TransferMethodSignature = "0xa9059cbb"
const erc20TransferEventSignature = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
const erc20NameSignature = "0x06fdde03"
const erc20SymbolSignature = "0x95d89b41"
const erc20DecimalsSignature = "0x313ce567"
const erc20BalanceOf = "0x70a08231"

var cachedContracts = make(map[string]*bchain.Erc20Contract)
var cachedContractsMux sync.Mutex

func addressFromPaddedHex(s string) (string, error) {
	var t big.Int
	var ok bool
	if has0xPrefix(s) {
		_, ok = t.SetString(s[2:], 16)
	} else {
		_, ok = t.SetString(s, 16)
	}
	if !ok {
		return "", errors.New("Data is not a number")
	}
	a := ethcommon.BigToAddress(&t)
	return a.String(), nil
}

func erc20GetTransfersFromLog(logs []*rpcLog) ([]bchain.Erc20Transfer, error) {
	var r []bchain.Erc20Transfer
	for _, l := range logs {
		if len(l.Topics) == 3 && l.Topics[0] == erc20TransferEventSignature {
			var t big.Int
			_, ok := t.SetString(l.Data, 0)
			if !ok {
				return nil, errors.New("Data is not a number")
			}
			from, err := addressFromPaddedHex(l.Topics[1])
			if err != nil {
				return nil, err
			}
			to, err := addressFromPaddedHex(l.Topics[2])
			if err != nil {
				return nil, err
			}
			r = append(r, bchain.Erc20Transfer{
				Contract: EIP55AddressFromAddress(l.Address),
				From:     EIP55AddressFromAddress(from),
				To:       EIP55AddressFromAddress(to),
				Tokens:   t,
			})
		}
	}
	return r, nil
}

func erc20GetTransfersFromTx(tx *rpcTransaction) ([]bchain.Erc20Transfer, error) {
	var r []bchain.Erc20Transfer
	if len(tx.Payload) == 128+len(erc20TransferMethodSignature) && strings.HasPrefix(tx.Payload, erc20TransferMethodSignature) {
		to, err := addressFromPaddedHex(tx.Payload[len(erc20TransferMethodSignature) : 64+len(erc20TransferMethodSignature)])
		if err != nil {
			return nil, err
		}
		var t big.Int
		_, ok := t.SetString(tx.Payload[len(erc20TransferMethodSignature)+64:], 16)
		if !ok {
			return nil, errors.New("Data is not a number")
		}
		r = append(r, bchain.Erc20Transfer{
			Contract: EIP55AddressFromAddress(tx.To),
			From:     EIP55AddressFromAddress(tx.From),
			To:       EIP55AddressFromAddress(to),
			Tokens:   t,
		})
	}
	return r, nil
}

func (b *EnergiRPC) ethCall(data, to string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), b.timeout)
	defer cancel()
	var r string
	err := b.rpc.CallContext(ctx, &r, "eth_call", map[string]interface{}{
		"data": data,
		"to":   to,
	}, "latest")
	if err != nil {
		return "", err
	}
	return r, nil
}

func parseErc20NumericProperty(contractDesc bchain.AddressDescriptor, data string) *big.Int {
	if has0xPrefix(data) {
		data = data[2:]
	}
	if len(data) == 64 {
		var n big.Int
		_, ok := n.SetString(data, 16)
		if ok {
			return &n
		}
	}
	if glog.V(1) {
		glog.Warning("Cannot parse '", data, "' for contract ", contractDesc)
	}
	return nil
}

func parseErc20StringProperty(contractDesc bchain.AddressDescriptor, data string) string {
	if has0xPrefix(data) {
		data = data[2:]
	}
	if len(data) > 128 {
		n := parseErc20NumericProperty(contractDesc, data[64:128])
		if n != nil {
			l := n.Uint64()
			if 2*int(l) <= len(data)-128 {
				b, err := hex.DecodeString(data[128 : 128+2*l])
				if err == nil {
					return string(b)
				}
			}
		}
	} else if len(data) == 64 {
		// allow string properties as 32 bytes of UTF-8 data
		b, err := hex.DecodeString(data)
		if err == nil {
			i := bytes.Index(b, []byte{0})
			if i > 0 {
				b = b[:i]
			}
			if utf8.Valid(b) {
				return string(b)
			}
		}
	}
	if glog.V(1) {
		glog.Warning("Cannot parse '", data, "' for contract ", contractDesc)
	}
	return ""
}

// EthereumTypeGetErc20ContractInfo returns information about ERC20 contract
func (b *EnergiRPC) EthereumTypeGetErc20ContractInfo(contractDesc bchain.AddressDescriptor) (*bchain.Erc20Contract, error) {
	cds := string(contractDesc)
	cachedContractsMux.Lock()
	contract, found := cachedContracts[cds]
	cachedContractsMux.Unlock()
	if !found {
		address := EIP55Address(contractDesc)
		data, err := b.ethCall(erc20NameSignature, address)
		if err != nil {
			return nil, err
		}
		name := parseErc20StringProperty(contractDesc, data)
		if name != "" {
			data, err = b.ethCall(erc20SymbolSignature, address)
			if err != nil {
				return nil, err
			}
			symbol := parseErc20StringProperty(contractDesc, data)
			data, err = b.ethCall(erc20DecimalsSignature, address)
			if err != nil {
				return nil, err
			}
			contract = &bchain.Erc20Contract{
				Contract: address,
				Name:     name,
				Symbol:   symbol,
			}
			d := parseErc20NumericProperty(contractDesc, data)
			if d != nil {
				contract.Decimals = int(uint8(d.Uint64()))
			} else {
				contract.Decimals = EnergiAmountDecimalPoint
			}
		} else {
			contract = nil
		}
		cachedContractsMux.Lock()
		cachedContracts[cds] = contract
		cachedContractsMux.Unlock()
	}
	return contract, nil
}

// EthereumTypeGetErc20ContractBalance returns balance of ERC20 contract for given address
func (b *EnergiRPC) EthereumTypeGetErc20ContractBalance(addrDesc, contractDesc bchain.AddressDescriptor) (*big.Int, error) {
	addr := EIP55Address(addrDesc)
	contract := EIP55Address(contractDesc)
	req := erc20BalanceOf + "0000000000000000000000000000000000000000000000000000000000000000"[len(addr)-2:] + addr[2:]
	data, err := b.ethCall(req, contract)
	if err != nil {
		return nil, err
	}
	r := parseErc20NumericProperty(contractDesc, data)
	if r == nil {
		return nil, errors.New("Invalid balance")
	}
	return r, nil
}
