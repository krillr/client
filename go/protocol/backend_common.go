package keybase1

import (
	rpc "github.com/keybase/go-framed-msgpack-rpc"
)

type BlockIdCombo struct {
	BlockHash string `codec:"blockHash" json:"blockHash"`
	ChargedTo UID    `codec:"chargedTo" json:"chargedTo"`
}

type ChallengeInfo struct {
	Now       int64  `codec:"now" json:"now"`
	Challenge string `codec:"challenge" json:"challenge"`
}

type BackendCommonInterface interface {
}

func BackendCommonProtocol(i BackendCommonInterface) rpc.Protocol {
	return rpc.Protocol{
		Name:    "keybase.1.backendCommon",
		Methods: map[string]rpc.ServeHandlerDescription{},
	}
}

type BackendCommonClient struct {
	Cli rpc.GenericClient
}
