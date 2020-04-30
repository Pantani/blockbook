// Code generated by protoc-gen-go. DO NOT EDIT.
// source: tx.proto

/*
Package energi is a generated protocol buffer package.

It is generated from these files:
	tx.proto

It has these top-level messages:
	ProtoCompleteTransaction
*/
package energi

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type ProtoCompleteTransaction struct {
	BlockNumber uint32                                `protobuf:"varint,1,opt,name=BlockNumber" json:"BlockNumber,omitempty"`
	BlockTime   uint64                                `protobuf:"varint,2,opt,name=BlockTime" json:"BlockTime,omitempty"`
	Tx          *ProtoCompleteTransaction_TxType      `protobuf:"bytes,3,opt,name=Tx" json:"Tx,omitempty"`
	Receipt     *ProtoCompleteTransaction_ReceiptType `protobuf:"bytes,4,opt,name=Receipt" json:"Receipt,omitempty"`
}

func (m *ProtoCompleteTransaction) Reset()                    { *m = ProtoCompleteTransaction{} }
func (m *ProtoCompleteTransaction) String() string            { return proto.CompactTextString(m) }
func (*ProtoCompleteTransaction) ProtoMessage()               {}
func (*ProtoCompleteTransaction) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *ProtoCompleteTransaction) GetBlockNumber() uint32 {
	if m != nil {
		return m.BlockNumber
	}
	return 0
}

func (m *ProtoCompleteTransaction) GetBlockTime() uint64 {
	if m != nil {
		return m.BlockTime
	}
	return 0
}

func (m *ProtoCompleteTransaction) GetTx() *ProtoCompleteTransaction_TxType {
	if m != nil {
		return m.Tx
	}
	return nil
}

func (m *ProtoCompleteTransaction) GetReceipt() *ProtoCompleteTransaction_ReceiptType {
	if m != nil {
		return m.Receipt
	}
	return nil
}

type ProtoCompleteTransaction_TxType struct {
	AccountNonce     uint64 `protobuf:"varint,1,opt,name=AccountNonce" json:"AccountNonce,omitempty"`
	GasPrice         []byte `protobuf:"bytes,2,opt,name=GasPrice,proto3" json:"GasPrice,omitempty"`
	GasLimit         uint64 `protobuf:"varint,3,opt,name=GasLimit" json:"GasLimit,omitempty"`
	Value            []byte `protobuf:"bytes,4,opt,name=Value,proto3" json:"Value,omitempty"`
	Payload          []byte `protobuf:"bytes,5,opt,name=Payload,proto3" json:"Payload,omitempty"`
	Hash             []byte `protobuf:"bytes,6,opt,name=NrgHash,proto3" json:"NrgHash,omitempty"`
	To               []byte `protobuf:"bytes,7,opt,name=To,proto3" json:"To,omitempty"`
	From             []byte `protobuf:"bytes,8,opt,name=From,proto3" json:"From,omitempty"`
	TransactionIndex uint32 `protobuf:"varint,9,opt,name=TransactionIndex" json:"TransactionIndex,omitempty"`
}

func (m *ProtoCompleteTransaction_TxType) Reset()         { *m = ProtoCompleteTransaction_TxType{} }
func (m *ProtoCompleteTransaction_TxType) String() string { return proto.CompactTextString(m) }
func (*ProtoCompleteTransaction_TxType) ProtoMessage()    {}
func (*ProtoCompleteTransaction_TxType) Descriptor() ([]byte, []int) {
	return fileDescriptor0, []int{0, 0}
}

func (m *ProtoCompleteTransaction_TxType) GetAccountNonce() uint64 {
	if m != nil {
		return m.AccountNonce
	}
	return 0
}

func (m *ProtoCompleteTransaction_TxType) GetGasPrice() []byte {
	if m != nil {
		return m.GasPrice
	}
	return nil
}

func (m *ProtoCompleteTransaction_TxType) GetGasLimit() uint64 {
	if m != nil {
		return m.GasLimit
	}
	return 0
}

func (m *ProtoCompleteTransaction_TxType) GetValue() []byte {
	if m != nil {
		return m.Value
	}
	return nil
}

func (m *ProtoCompleteTransaction_TxType) GetPayload() []byte {
	if m != nil {
		return m.Payload
	}
	return nil
}

func (m *ProtoCompleteTransaction_TxType) GetHash() []byte {
	if m != nil {
		return m.Hash
	}
	return nil
}

func (m *ProtoCompleteTransaction_TxType) GetTo() []byte {
	if m != nil {
		return m.To
	}
	return nil
}

func (m *ProtoCompleteTransaction_TxType) GetFrom() []byte {
	if m != nil {
		return m.From
	}
	return nil
}

func (m *ProtoCompleteTransaction_TxType) GetTransactionIndex() uint32 {
	if m != nil {
		return m.TransactionIndex
	}
	return 0
}

type ProtoCompleteTransaction_ReceiptType struct {
	GasUsed []byte                                          `protobuf:"bytes,1,opt,name=GasUsed,proto3" json:"GasUsed,omitempty"`
	Status  []byte                                          `protobuf:"bytes,2,opt,name=Status,proto3" json:"Status,omitempty"`
	Log     []*ProtoCompleteTransaction_ReceiptType_LogType `protobuf:"bytes,3,rep,name=Log" json:"Log,omitempty"`
}

func (m *ProtoCompleteTransaction_ReceiptType) Reset()         { *m = ProtoCompleteTransaction_ReceiptType{} }
func (m *ProtoCompleteTransaction_ReceiptType) String() string { return proto.CompactTextString(m) }
func (*ProtoCompleteTransaction_ReceiptType) ProtoMessage()    {}
func (*ProtoCompleteTransaction_ReceiptType) Descriptor() ([]byte, []int) {
	return fileDescriptor0, []int{0, 1}
}

func (m *ProtoCompleteTransaction_ReceiptType) GetGasUsed() []byte {
	if m != nil {
		return m.GasUsed
	}
	return nil
}

func (m *ProtoCompleteTransaction_ReceiptType) GetStatus() []byte {
	if m != nil {
		return m.Status
	}
	return nil
}

func (m *ProtoCompleteTransaction_ReceiptType) GetLog() []*ProtoCompleteTransaction_ReceiptType_LogType {
	if m != nil {
		return m.Log
	}
	return nil
}

type ProtoCompleteTransaction_ReceiptType_LogType struct {
	Address []byte   `protobuf:"bytes,1,opt,name=Address,proto3" json:"Address,omitempty"`
	Data    []byte   `protobuf:"bytes,2,opt,name=Data,proto3" json:"Data,omitempty"`
	Topics  [][]byte `protobuf:"bytes,3,rep,name=Topics,proto3" json:"Topics,omitempty"`
}

func (m *ProtoCompleteTransaction_ReceiptType_LogType) Reset() {
	*m = ProtoCompleteTransaction_ReceiptType_LogType{}
}
func (m *ProtoCompleteTransaction_ReceiptType_LogType) String() string {
	return proto.CompactTextString(m)
}
func (*ProtoCompleteTransaction_ReceiptType_LogType) ProtoMessage() {}
func (*ProtoCompleteTransaction_ReceiptType_LogType) Descriptor() ([]byte, []int) {
	return fileDescriptor0, []int{0, 1, 0}
}

func (m *ProtoCompleteTransaction_ReceiptType_LogType) GetAddress() []byte {
	if m != nil {
		return m.Address
	}
	return nil
}

func (m *ProtoCompleteTransaction_ReceiptType_LogType) GetData() []byte {
	if m != nil {
		return m.Data
	}
	return nil
}

func (m *ProtoCompleteTransaction_ReceiptType_LogType) GetTopics() [][]byte {
	if m != nil {
		return m.Topics
	}
	return nil
}

func init() {
	proto.RegisterType((*ProtoCompleteTransaction)(nil), "energi.ProtoCompleteTransaction")
	proto.RegisterType((*ProtoCompleteTransaction_TxType)(nil), "energi.ProtoCompleteTransaction.TxType")
	proto.RegisterType((*ProtoCompleteTransaction_ReceiptType)(nil), "energi.ProtoCompleteTransaction.ReceiptType")
	proto.RegisterType((*ProtoCompleteTransaction_ReceiptType_LogType)(nil), "energi.ProtoCompleteTransaction.ReceiptType.LogType")
}

func init() { proto.RegisterFile("tx.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 393 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x92, 0xdf, 0x8a, 0xd4, 0x30,
	0x14, 0xc6, 0xe9, 0x9f, 0xf9, 0xb3, 0xa7, 0x55, 0x24, 0x88, 0x84, 0xe2, 0x45, 0x59, 0xbc, 0xa8,
	0x5e, 0x14, 0x5c, 0x7d, 0x81, 0x75, 0xc4, 0x55, 0x18, 0xd6, 0x21, 0x46, 0xef, 0xb3, 0x69, 0xd8,
	0x29, 0xb6, 0x4d, 0x69, 0x52, 0xe8, 0xbe, 0x91, 0x2f, 0xe4, 0xbb, 0x78, 0x29, 0x39, 0x4d, 0xd7,
	0x11, 0x51, 0xbc, 0x3b, 0xbf, 0x6f, 0xce, 0x37, 0xf9, 0xbe, 0xa4, 0xb0, 0xb5, 0x53, 0xd9, 0x0f,
	0xda, 0x6a, 0x12, 0x29, 0x7b, 0x3c, 0xff, 0xb6, 0x02, 0x7a, 0x70, 0xb8, 0xd3, 0x6d, 0xdf, 0x28,
	0xab, 0xf8, 0x20, 0x3a, 0x23, 0xa4, 0xad, 0x75, 0x47, 0x72, 0x48, 0xde, 0x34, 0x5a, 0x7e, 0xbd,
	0x1e, 0xdb, 0x1b, 0x35, 0xd0, 0x20, 0x0f, 0x8a, 0x07, 0xec, 0x54, 0x22, 0x4f, 0xe1, 0x0c, 0x91,
	0xd7, 0xad, 0xa2, 0x61, 0x1e, 0x14, 0x31, 0xfb, 0x25, 0x90, 0xd7, 0x10, 0xf2, 0x89, 0x46, 0x79,
	0x50, 0x24, 0x17, 0xcf, 0x4a, 0x65, 0x8f, 0xe5, 0xdf, 0x8e, 0x2a, 0xf9, 0xc4, 0xef, 0x7a, 0xc5,
	0x42, 0x3e, 0x91, 0x1d, 0x6c, 0x98, 0x92, 0xaa, 0xee, 0x2d, 0x8d, 0xd1, 0xfa, 0xfc, 0xdf, 0x56,
	0xbf, 0x8c, 0xfe, 0xc5, 0x99, 0xfd, 0x08, 0x60, 0x3d, 0xff, 0x27, 0x39, 0x87, 0xf4, 0x52, 0x4a,
	0x3d, 0x76, 0xf6, 0x5a, 0x77, 0x52, 0x61, 0x8d, 0x98, 0xfd, 0xa6, 0x91, 0x0c, 0xb6, 0x57, 0xc2,
	0x1c, 0x86, 0x5a, 0xce, 0x35, 0x52, 0x76, 0xcf, 0xfe, 0xb7, 0x7d, 0xdd, 0xd6, 0x16, 0xbb, 0xc4,
	0xec, 0x9e, 0xc9, 0x63, 0x58, 0x7d, 0x11, 0xcd, 0xa8, 0x30, 0x69, 0xca, 0x66, 0x20, 0x14, 0x36,
	0x07, 0x71, 0xd7, 0x68, 0x51, 0xd1, 0x15, 0xea, 0x0b, 0x12, 0x02, 0xf1, 0x7b, 0x61, 0x8e, 0x74,
	0x8d, 0x32, 0xce, 0xe4, 0x21, 0x84, 0x5c, 0xd3, 0x0d, 0x2a, 0x21, 0xd7, 0x6e, 0xe7, 0xdd, 0xa0,
	0x5b, 0xba, 0x9d, 0x77, 0xdc, 0x4c, 0x5e, 0xc0, 0xa3, 0x93, 0xca, 0x1f, 0xba, 0x4a, 0x4d, 0xf4,
	0x0c, 0x9f, 0xe3, 0x0f, 0x3d, 0xfb, 0x1e, 0x40, 0x72, 0x72, 0x27, 0x2e, 0xcd, 0x95, 0x30, 0x9f,
	0x8d, 0xaa, 0xb0, 0x7a, 0xca, 0x16, 0x24, 0x4f, 0x60, 0xfd, 0xc9, 0x0a, 0x3b, 0x1a, 0xdf, 0xd9,
	0x13, 0xd9, 0x41, 0xb4, 0xd7, 0xb7, 0x34, 0xca, 0xa3, 0x22, 0xb9, 0x78, 0xf9, 0xdf, 0xb7, 0x5f,
	0xee, 0xf5, 0x2d, 0xbe, 0x82, 0x73, 0x67, 0x1f, 0x61, 0xe3, 0xd9, 0x25, 0xb8, 0xac, 0xaa, 0x41,
	0x19, 0xb3, 0x24, 0xf0, 0xe8, 0xba, 0xbe, 0x15, 0x56, 0xf8, 0xf3, 0x71, 0x76, 0xa9, 0xb8, 0xee,
	0x6b, 0x69, 0x30, 0x40, 0xca, 0x3c, 0xdd, 0xac, 0xf1, 0xb3, 0x7d, 0xf5, 0x33, 0x00, 0x00, 0xff,
	0xff, 0xde, 0xd5, 0x28, 0xa3, 0xc2, 0x02, 0x00, 0x00,
}
