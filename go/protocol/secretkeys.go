package keybase1

import (
	rpc "github.com/keybase/go-framed-msgpack-rpc"
	context "golang.org/x/net/context"
)

type NaclSigningKeyPublic [32]byte
type NaclSigningKeyPrivate [64]byte
type NaclDHKeyPublic [32]byte
type NaclDHKeyPrivate [32]byte
type SecretKeys struct {
	Signing    NaclSigningKeyPrivate `codec:"signing" json:"signing"`
	Encryption NaclDHKeyPrivate      `codec:"encryption" json:"encryption"`
}

type GetSecretKeysArg struct {
	SessionID int `codec:"sessionID" json:"sessionID"`
}

type SecretKeysInterface interface {
	GetSecretKeys(context.Context, int) (SecretKeys, error)
}

func SecretKeysProtocol(i SecretKeysInterface) rpc.Protocol {
	return rpc.Protocol{
		Name: "keybase.1.SecretKeys",
		Methods: map[string]rpc.ServeHandlerDescription{
			"getSecretKeys": {
				MakeArg: func() interface{} {
					ret := make([]GetSecretKeysArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]GetSecretKeysArg)
					if !ok {
						err = rpc.NewTypeError((*[]GetSecretKeysArg)(nil), args)
						return
					}
					ret, err = i.GetSecretKeys(ctx, (*typedArgs)[0].SessionID)
					return
				},
				MethodType: rpc.MethodCall,
			},
		},
	}
}

type SecretKeysClient struct {
	Cli rpc.GenericClient
}

func (c SecretKeysClient) GetSecretKeys(ctx context.Context, sessionID int) (res SecretKeys, err error) {
	__arg := GetSecretKeysArg{SessionID: sessionID}
	err = c.Cli.Call(ctx, "keybase.1.SecretKeys.getSecretKeys", []interface{}{__arg}, &res)
	return
}
