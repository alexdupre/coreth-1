package core

import (
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/flare-foundation/coreth/core/types"
	"github.com/flare-foundation/coreth/core/vm"
)

type mockMessage struct {
	from       common.Address
	to         common.Address
	gas        uint64
	gasPrice   *big.Int
	gasFeeCap  *big.Int
	gasTipCap  *big.Int
	value      *big.Int
	data       []byte
	accessList types.AccessList
}

func (m *mockMessage) From() common.Address         { return m.from }
func (m *mockMessage) To() *common.Address          { return &m.to }
func (m *mockMessage) GasPrice() *big.Int           { return m.gasPrice }
func (m *mockMessage) GasFeeCap() *big.Int          { return m.gasFeeCap }
func (m *mockMessage) GasTipCap() *big.Int          { return m.gasTipCap }
func (m *mockMessage) Value() *big.Int              { return m.value }
func (m *mockMessage) Gas() uint64                  { return m.gas }
func (m *mockMessage) Nonce() uint64                { return 0 }
func (m *mockMessage) Data() []byte                 { return m.data }
func (m *mockMessage) AccessList() types.AccessList { return m.accessList }
func (m *mockMessage) IsFake() bool                 { return true }

type mockStateConnectorCaller struct {
	context  vm.BlockContext
	msg      *mockMessage
	CallFunc func(context vm.BlockContext, caller vm.ContractRef, addr common.Address, input []byte, gas uint64, value *big.Int) (ret []byte, leftOverGas uint64, err error)
}

func (m *mockStateConnectorCaller) Call(caller vm.ContractRef, addr common.Address, input []byte, gas uint64,
	value *big.Int) (ret []byte, leftOverGas uint64, err error) {

	return m.CallFunc(m.context, caller, addr, input, gas, value)
}

func (m *mockStateConnectorCaller) WithBlockContext(bc vm.BlockContext) { m.context = bc }

func (m *mockStateConnectorCaller) BlockContext() vm.BlockContext { return m.context }

func buildStateConnectorMock(from string, addr common.Address) (*mockMessage, *mockStateConnectorCaller) {
	msg := mockMessage{
		from: common.BytesToAddress([]byte(from)),
	}
	scc := mockStateConnectorCaller{
		msg: &msg,
		context: vm.BlockContext{
			Coinbase: addr,
		},
	}
	return &msg, &scc
}

func TestStateTransition_FinalisePreviousRound(t *testing.T) {
	currentRoundNumber := []byte("222")
	coinbaseAddress := common.BigToAddress(big.NewInt(1000))

	t.Run("nominal case", func(t *testing.T) {
		t.Parallel()
		mockMsg, mockSCC := buildStateConnectorMock("nominal case", coinbaseAddress)

		mockSCC.CallFunc = func(context vm.BlockContext, caller vm.ContractRef, addr common.Address, input []byte, gas uint64, value *big.Int) (ret []byte, leftOverGas uint64, err error) {
			voter1 := common.BytesToHash([]byte("voter1"))
			voter2 := common.BytesToHash([]byte("voter2"))
			rootHash := []byte("some_hash")
			if caller == vm.AccountRef(mockMsg.From()) {
				if addr == common.HexToAddress(GetPrioritisedFTSOContract(nil)) {
					return []byte("voter"), 0, nil
				}
				if addr == common.BytesToAddress([]byte("voter")) {
					return append([]byte{}, append(voter1.Bytes(), voter2.Bytes()...)...), 0, nil
				}
			}
			if caller == vm.AccountRef(common.BytesToAddress(voter1.Bytes())) ||
				caller == vm.AccountRef(common.BytesToAddress(voter2.Bytes())) {
				return rootHash, 0, nil
			}
			if context.Coinbase != stateConnectorCoinbaseSignalAddr {
				return nil, 0, fmt.Errorf("invalid coinbase address: expected %v, got %v", stateConnectorCoinbaseSignalAddr, context.Coinbase)
			}
			return nil, 0, nil
		}

		c := newConnector(mockSCC, mockMsg)
		err := c.finalizePreviousRound(big.NewInt(10), big.NewInt(10), currentRoundNumber)
		require.NoError(t, err)
		assert.Equal(t, coinbaseAddress, mockSCC.context.Coinbase, "coinbase address should be changed to the original address")
	})
	t.Run("handles voter whitelister error", func(t *testing.T) {
		t.Parallel()
		mockMsg, mockSCC := buildStateConnectorMock("", coinbaseAddress)

		mockSCC.CallFunc = func(context vm.BlockContext, caller vm.ContractRef, addr common.Address, input []byte, gas uint64, value *big.Int) (ret []byte, leftOverGas uint64, err error) {
			return nil, 0, errors.New("voter whitelister error")
		}

		c := newConnector(mockSCC, mockMsg)
		err := c.finalizePreviousRound(big.NewInt(10), big.NewInt(10), currentRoundNumber)
		assert.EqualError(t, err, "failed to get VoterWhitelister contract: voter whitelister error")
	})
	t.Run("handles list price provider error", func(t *testing.T) {
		t.Parallel()
		mockMsg, mockSCC := buildStateConnectorMock("", coinbaseAddress)

		mockSCC.CallFunc = func(context vm.BlockContext, caller vm.ContractRef, addr common.Address, input []byte, gas uint64, value *big.Int) (ret []byte, leftOverGas uint64, err error) {
			if addr == common.HexToAddress(GetPrioritisedFTSOContract(nil)) {
				return []byte("voter"), 0, nil
			}
			return nil, 0, errors.New("list price provider error")
		}

		c := newConnector(mockSCC, mockMsg)
		err := c.finalizePreviousRound(big.NewInt(10), big.NewInt(10), currentRoundNumber)
		assert.EqualError(t, err, "failed to get FTSO price providers: list price provider error")
	})
	t.Run("handles finalization error", func(t *testing.T) {
		t.Parallel()
		mockMsg, mockSCC := buildStateConnectorMock("", coinbaseAddress)

		mockSCC.CallFunc = func(context vm.BlockContext, caller vm.ContractRef, addr common.Address, input []byte, gas uint64, value *big.Int) (ret []byte, leftOverGas uint64, err error) {
			voter1 := common.BytesToHash([]byte("voter1"))
			voter2 := common.BytesToHash([]byte("voter2"))
			rootHash := []byte("some_hash")
			if caller == vm.AccountRef(mockMsg.From()) {
				if addr == common.HexToAddress(GetPrioritisedFTSOContract(nil)) {
					return []byte("voter"), 0, nil
				}
				if addr == common.BytesToAddress([]byte("voter")) {
					return append([]byte{}, append(voter1.Bytes(), voter2.Bytes()...)...), 0, nil
				}
			}
			if caller == vm.AccountRef(common.BytesToAddress(voter1.Bytes())) ||
				caller == vm.AccountRef(common.BytesToAddress(voter2.Bytes())) {
				return rootHash, 0, nil
			}
			if context.Coinbase != stateConnectorCoinbaseSignalAddr {
				return nil, 0, fmt.Errorf("invalid coinbase address: expected %v, got %v", stateConnectorCoinbaseSignalAddr, context.Coinbase)
			}
			return nil, 0, errors.New("finalization error")
		}

		c := newConnector(mockSCC, mockMsg)
		err := c.finalizePreviousRound(big.NewInt(10), big.NewInt(10), currentRoundNumber)
		assert.EqualError(t, err, "finalization error")
		assert.Equal(t, coinbaseAddress, mockSCC.context.Coinbase, "coinbase address should be changed to the original address")
	})
}
