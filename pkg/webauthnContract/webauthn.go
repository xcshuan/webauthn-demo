// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package webauthnContract

import (
	"errors"
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = errors.New
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
	_ = abi.ConvertType
)

// WebauthnContractMetaData contains all meta data concerning the WebauthnContract contract.
var WebauthnContractMetaData = &bind.MetaData{
	ABI: "[{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"_data\",\"type\":\"bytes\"},{\"internalType\":\"uint256\",\"name\":\"_index\",\"type\":\"uint256\"}],\"name\":\"ReadBytes32OutOfBounds\",\"type\":\"error\"},{\"inputs\":[{\"internalType\":\"string\",\"name\":\"userName\",\"type\":\"string\"},{\"internalType\":\"uint256\",\"name\":\"sigX\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"sigY\",\"type\":\"uint256\"},{\"internalType\":\"bytes\",\"name\":\"challenge\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"authenticatorData\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"clientDataJSONPre\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"clientDataJSONPost\",\"type\":\"bytes\"}],\"name\":\"authenticateUseES256\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"validationData\",\"type\":\"uint256\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"string\",\"name\":\"userName\",\"type\":\"string\"},{\"internalType\":\"bytes\",\"name\":\"signature\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"challenge\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"authenticatorData\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"clientDataJSONPre\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"clientDataJSONPost\",\"type\":\"bytes\"}],\"name\":\"authenticateUseRS256\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"validationData\",\"type\":\"uint256\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"name\":\"authorisedP256Keys\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"pubKeyX\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"pubKeyY\",\"type\":\"uint256\"},{\"internalType\":\"string\",\"name\":\"keyId\",\"type\":\"string\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"name\":\"authorisedRSAKeys\",\"outputs\":[{\"internalType\":\"bytes\",\"name\":\"n\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"e\",\"type\":\"bytes\"},{\"internalType\":\"string\",\"name\":\"keyId\",\"type\":\"string\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"string\",\"name\":\"userName\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"keyId\",\"type\":\"string\"},{\"internalType\":\"uint256\",\"name\":\"pubKeyX\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"pubKeyY\",\"type\":\"uint256\"}],\"name\":\"registerP256Key\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"string\",\"name\":\"userName\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"keyId\",\"type\":\"string\"},{\"internalType\":\"bytes\",\"name\":\"n\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"e\",\"type\":\"bytes\"}],\"name\":\"registerRSAKey\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]",
}

// WebauthnContractABI is the input ABI used to generate the binding from.
// Deprecated: Use WebauthnContractMetaData.ABI instead.
var WebauthnContractABI = WebauthnContractMetaData.ABI

// WebauthnContract is an auto generated Go binding around an Ethereum contract.
type WebauthnContract struct {
	WebauthnContractCaller     // Read-only binding to the contract
	WebauthnContractTransactor // Write-only binding to the contract
	WebauthnContractFilterer   // Log filterer for contract events
}

// WebauthnContractCaller is an auto generated read-only Go binding around an Ethereum contract.
type WebauthnContractCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// WebauthnContractTransactor is an auto generated write-only Go binding around an Ethereum contract.
type WebauthnContractTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// WebauthnContractFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type WebauthnContractFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// WebauthnContractSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type WebauthnContractSession struct {
	Contract     *WebauthnContract // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// WebauthnContractCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type WebauthnContractCallerSession struct {
	Contract *WebauthnContractCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts           // Call options to use throughout this session
}

// WebauthnContractTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type WebauthnContractTransactorSession struct {
	Contract     *WebauthnContractTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts           // Transaction auth options to use throughout this session
}

// WebauthnContractRaw is an auto generated low-level Go binding around an Ethereum contract.
type WebauthnContractRaw struct {
	Contract *WebauthnContract // Generic contract binding to access the raw methods on
}

// WebauthnContractCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type WebauthnContractCallerRaw struct {
	Contract *WebauthnContractCaller // Generic read-only contract binding to access the raw methods on
}

// WebauthnContractTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type WebauthnContractTransactorRaw struct {
	Contract *WebauthnContractTransactor // Generic write-only contract binding to access the raw methods on
}

// NewWebauthnContract creates a new instance of WebauthnContract, bound to a specific deployed contract.
func NewWebauthnContract(address common.Address, backend bind.ContractBackend) (*WebauthnContract, error) {
	contract, err := bindWebauthnContract(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &WebauthnContract{WebauthnContractCaller: WebauthnContractCaller{contract: contract}, WebauthnContractTransactor: WebauthnContractTransactor{contract: contract}, WebauthnContractFilterer: WebauthnContractFilterer{contract: contract}}, nil
}

// NewWebauthnContractCaller creates a new read-only instance of WebauthnContract, bound to a specific deployed contract.
func NewWebauthnContractCaller(address common.Address, caller bind.ContractCaller) (*WebauthnContractCaller, error) {
	contract, err := bindWebauthnContract(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &WebauthnContractCaller{contract: contract}, nil
}

// NewWebauthnContractTransactor creates a new write-only instance of WebauthnContract, bound to a specific deployed contract.
func NewWebauthnContractTransactor(address common.Address, transactor bind.ContractTransactor) (*WebauthnContractTransactor, error) {
	contract, err := bindWebauthnContract(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &WebauthnContractTransactor{contract: contract}, nil
}

// NewWebauthnContractFilterer creates a new log filterer instance of WebauthnContract, bound to a specific deployed contract.
func NewWebauthnContractFilterer(address common.Address, filterer bind.ContractFilterer) (*WebauthnContractFilterer, error) {
	contract, err := bindWebauthnContract(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &WebauthnContractFilterer{contract: contract}, nil
}

// bindWebauthnContract binds a generic wrapper to an already deployed contract.
func bindWebauthnContract(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := WebauthnContractMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_WebauthnContract *WebauthnContractRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _WebauthnContract.Contract.WebauthnContractCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_WebauthnContract *WebauthnContractRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _WebauthnContract.Contract.WebauthnContractTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_WebauthnContract *WebauthnContractRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _WebauthnContract.Contract.WebauthnContractTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_WebauthnContract *WebauthnContractCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _WebauthnContract.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_WebauthnContract *WebauthnContractTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _WebauthnContract.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_WebauthnContract *WebauthnContractTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _WebauthnContract.Contract.contract.Transact(opts, method, params...)
}

// AuthorisedP256Keys is a free data retrieval call binding the contract method 0x8be9a5e4.
//
// Solidity: function authorisedP256Keys(string ) view returns(uint256 pubKeyX, uint256 pubKeyY, string keyId)
func (_WebauthnContract *WebauthnContractCaller) AuthorisedP256Keys(opts *bind.CallOpts, arg0 string) (struct {
	PubKeyX *big.Int
	PubKeyY *big.Int
	KeyId   string
}, error) {
	var out []interface{}
	err := _WebauthnContract.contract.Call(opts, &out, "authorisedP256Keys", arg0)

	outstruct := new(struct {
		PubKeyX *big.Int
		PubKeyY *big.Int
		KeyId   string
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.PubKeyX = *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)
	outstruct.PubKeyY = *abi.ConvertType(out[1], new(*big.Int)).(**big.Int)
	outstruct.KeyId = *abi.ConvertType(out[2], new(string)).(*string)

	return *outstruct, err

}

// AuthorisedP256Keys is a free data retrieval call binding the contract method 0x8be9a5e4.
//
// Solidity: function authorisedP256Keys(string ) view returns(uint256 pubKeyX, uint256 pubKeyY, string keyId)
func (_WebauthnContract *WebauthnContractSession) AuthorisedP256Keys(arg0 string) (struct {
	PubKeyX *big.Int
	PubKeyY *big.Int
	KeyId   string
}, error) {
	return _WebauthnContract.Contract.AuthorisedP256Keys(&_WebauthnContract.CallOpts, arg0)
}

// AuthorisedP256Keys is a free data retrieval call binding the contract method 0x8be9a5e4.
//
// Solidity: function authorisedP256Keys(string ) view returns(uint256 pubKeyX, uint256 pubKeyY, string keyId)
func (_WebauthnContract *WebauthnContractCallerSession) AuthorisedP256Keys(arg0 string) (struct {
	PubKeyX *big.Int
	PubKeyY *big.Int
	KeyId   string
}, error) {
	return _WebauthnContract.Contract.AuthorisedP256Keys(&_WebauthnContract.CallOpts, arg0)
}

// AuthorisedRSAKeys is a free data retrieval call binding the contract method 0x920cf6bd.
//
// Solidity: function authorisedRSAKeys(string ) view returns(bytes n, bytes e, string keyId)
func (_WebauthnContract *WebauthnContractCaller) AuthorisedRSAKeys(opts *bind.CallOpts, arg0 string) (struct {
	N     []byte
	E     []byte
	KeyId string
}, error) {
	var out []interface{}
	err := _WebauthnContract.contract.Call(opts, &out, "authorisedRSAKeys", arg0)

	outstruct := new(struct {
		N     []byte
		E     []byte
		KeyId string
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.N = *abi.ConvertType(out[0], new([]byte)).(*[]byte)
	outstruct.E = *abi.ConvertType(out[1], new([]byte)).(*[]byte)
	outstruct.KeyId = *abi.ConvertType(out[2], new(string)).(*string)

	return *outstruct, err

}

// AuthorisedRSAKeys is a free data retrieval call binding the contract method 0x920cf6bd.
//
// Solidity: function authorisedRSAKeys(string ) view returns(bytes n, bytes e, string keyId)
func (_WebauthnContract *WebauthnContractSession) AuthorisedRSAKeys(arg0 string) (struct {
	N     []byte
	E     []byte
	KeyId string
}, error) {
	return _WebauthnContract.Contract.AuthorisedRSAKeys(&_WebauthnContract.CallOpts, arg0)
}

// AuthorisedRSAKeys is a free data retrieval call binding the contract method 0x920cf6bd.
//
// Solidity: function authorisedRSAKeys(string ) view returns(bytes n, bytes e, string keyId)
func (_WebauthnContract *WebauthnContractCallerSession) AuthorisedRSAKeys(arg0 string) (struct {
	N     []byte
	E     []byte
	KeyId string
}, error) {
	return _WebauthnContract.Contract.AuthorisedRSAKeys(&_WebauthnContract.CallOpts, arg0)
}

// AuthenticateUseES256 is a paid mutator transaction binding the contract method 0xc5f2e782.
//
// Solidity: function authenticateUseES256(string userName, uint256 sigX, uint256 sigY, bytes challenge, bytes authenticatorData, bytes clientDataJSONPre, bytes clientDataJSONPost) returns(uint256 validationData)
func (_WebauthnContract *WebauthnContractTransactor) AuthenticateUseES256(opts *bind.TransactOpts, userName string, sigX *big.Int, sigY *big.Int, challenge []byte, authenticatorData []byte, clientDataJSONPre []byte, clientDataJSONPost []byte) (*types.Transaction, error) {
	return _WebauthnContract.contract.Transact(opts, "authenticateUseES256", userName, sigX, sigY, challenge, authenticatorData, clientDataJSONPre, clientDataJSONPost)
}

// AuthenticateUseES256 is a paid mutator transaction binding the contract method 0xc5f2e782.
//
// Solidity: function authenticateUseES256(string userName, uint256 sigX, uint256 sigY, bytes challenge, bytes authenticatorData, bytes clientDataJSONPre, bytes clientDataJSONPost) returns(uint256 validationData)
func (_WebauthnContract *WebauthnContractSession) AuthenticateUseES256(userName string, sigX *big.Int, sigY *big.Int, challenge []byte, authenticatorData []byte, clientDataJSONPre []byte, clientDataJSONPost []byte) (*types.Transaction, error) {
	return _WebauthnContract.Contract.AuthenticateUseES256(&_WebauthnContract.TransactOpts, userName, sigX, sigY, challenge, authenticatorData, clientDataJSONPre, clientDataJSONPost)
}

// AuthenticateUseES256 is a paid mutator transaction binding the contract method 0xc5f2e782.
//
// Solidity: function authenticateUseES256(string userName, uint256 sigX, uint256 sigY, bytes challenge, bytes authenticatorData, bytes clientDataJSONPre, bytes clientDataJSONPost) returns(uint256 validationData)
func (_WebauthnContract *WebauthnContractTransactorSession) AuthenticateUseES256(userName string, sigX *big.Int, sigY *big.Int, challenge []byte, authenticatorData []byte, clientDataJSONPre []byte, clientDataJSONPost []byte) (*types.Transaction, error) {
	return _WebauthnContract.Contract.AuthenticateUseES256(&_WebauthnContract.TransactOpts, userName, sigX, sigY, challenge, authenticatorData, clientDataJSONPre, clientDataJSONPost)
}

// AuthenticateUseRS256 is a paid mutator transaction binding the contract method 0xdeaa74ce.
//
// Solidity: function authenticateUseRS256(string userName, bytes signature, bytes challenge, bytes authenticatorData, bytes clientDataJSONPre, bytes clientDataJSONPost) returns(uint256 validationData)
func (_WebauthnContract *WebauthnContractTransactor) AuthenticateUseRS256(opts *bind.TransactOpts, userName string, signature []byte, challenge []byte, authenticatorData []byte, clientDataJSONPre []byte, clientDataJSONPost []byte) (*types.Transaction, error) {
	return _WebauthnContract.contract.Transact(opts, "authenticateUseRS256", userName, signature, challenge, authenticatorData, clientDataJSONPre, clientDataJSONPost)
}

// AuthenticateUseRS256 is a paid mutator transaction binding the contract method 0xdeaa74ce.
//
// Solidity: function authenticateUseRS256(string userName, bytes signature, bytes challenge, bytes authenticatorData, bytes clientDataJSONPre, bytes clientDataJSONPost) returns(uint256 validationData)
func (_WebauthnContract *WebauthnContractSession) AuthenticateUseRS256(userName string, signature []byte, challenge []byte, authenticatorData []byte, clientDataJSONPre []byte, clientDataJSONPost []byte) (*types.Transaction, error) {
	return _WebauthnContract.Contract.AuthenticateUseRS256(&_WebauthnContract.TransactOpts, userName, signature, challenge, authenticatorData, clientDataJSONPre, clientDataJSONPost)
}

// AuthenticateUseRS256 is a paid mutator transaction binding the contract method 0xdeaa74ce.
//
// Solidity: function authenticateUseRS256(string userName, bytes signature, bytes challenge, bytes authenticatorData, bytes clientDataJSONPre, bytes clientDataJSONPost) returns(uint256 validationData)
func (_WebauthnContract *WebauthnContractTransactorSession) AuthenticateUseRS256(userName string, signature []byte, challenge []byte, authenticatorData []byte, clientDataJSONPre []byte, clientDataJSONPost []byte) (*types.Transaction, error) {
	return _WebauthnContract.Contract.AuthenticateUseRS256(&_WebauthnContract.TransactOpts, userName, signature, challenge, authenticatorData, clientDataJSONPre, clientDataJSONPost)
}

// RegisterP256Key is a paid mutator transaction binding the contract method 0x235b92e6.
//
// Solidity: function registerP256Key(string userName, string keyId, uint256 pubKeyX, uint256 pubKeyY) returns()
func (_WebauthnContract *WebauthnContractTransactor) RegisterP256Key(opts *bind.TransactOpts, userName string, keyId string, pubKeyX *big.Int, pubKeyY *big.Int) (*types.Transaction, error) {
	return _WebauthnContract.contract.Transact(opts, "registerP256Key", userName, keyId, pubKeyX, pubKeyY)
}

// RegisterP256Key is a paid mutator transaction binding the contract method 0x235b92e6.
//
// Solidity: function registerP256Key(string userName, string keyId, uint256 pubKeyX, uint256 pubKeyY) returns()
func (_WebauthnContract *WebauthnContractSession) RegisterP256Key(userName string, keyId string, pubKeyX *big.Int, pubKeyY *big.Int) (*types.Transaction, error) {
	return _WebauthnContract.Contract.RegisterP256Key(&_WebauthnContract.TransactOpts, userName, keyId, pubKeyX, pubKeyY)
}

// RegisterP256Key is a paid mutator transaction binding the contract method 0x235b92e6.
//
// Solidity: function registerP256Key(string userName, string keyId, uint256 pubKeyX, uint256 pubKeyY) returns()
func (_WebauthnContract *WebauthnContractTransactorSession) RegisterP256Key(userName string, keyId string, pubKeyX *big.Int, pubKeyY *big.Int) (*types.Transaction, error) {
	return _WebauthnContract.Contract.RegisterP256Key(&_WebauthnContract.TransactOpts, userName, keyId, pubKeyX, pubKeyY)
}

// RegisterRSAKey is a paid mutator transaction binding the contract method 0xd4a1c0a0.
//
// Solidity: function registerRSAKey(string userName, string keyId, bytes n, bytes e) returns()
func (_WebauthnContract *WebauthnContractTransactor) RegisterRSAKey(opts *bind.TransactOpts, userName string, keyId string, n []byte, e []byte) (*types.Transaction, error) {
	return _WebauthnContract.contract.Transact(opts, "registerRSAKey", userName, keyId, n, e)
}

// RegisterRSAKey is a paid mutator transaction binding the contract method 0xd4a1c0a0.
//
// Solidity: function registerRSAKey(string userName, string keyId, bytes n, bytes e) returns()
func (_WebauthnContract *WebauthnContractSession) RegisterRSAKey(userName string, keyId string, n []byte, e []byte) (*types.Transaction, error) {
	return _WebauthnContract.Contract.RegisterRSAKey(&_WebauthnContract.TransactOpts, userName, keyId, n, e)
}

// RegisterRSAKey is a paid mutator transaction binding the contract method 0xd4a1c0a0.
//
// Solidity: function registerRSAKey(string userName, string keyId, bytes n, bytes e) returns()
func (_WebauthnContract *WebauthnContractTransactorSession) RegisterRSAKey(userName string, keyId string, n []byte, e []byte) (*types.Transaction, error) {
	return _WebauthnContract.Contract.RegisterRSAKey(&_WebauthnContract.TransactOpts, userName, keyId, n, e)
}

