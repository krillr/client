package keybase1

import (
	rpc "github.com/keybase/go-framed-msgpack-rpc"
	context "golang.org/x/net/context"
)

type PassphraseStream struct {
	PassphraseStream []byte `codec:"passphraseStream" json:"passphraseStream"`
	Generation       int    `codec:"generation" json:"generation"`
}

type SessionToken string
type CsrfToken string
type HelloRes string
type HelloArg struct {
	Uid     UID              `codec:"uid" json:"uid"`
	Token   SessionToken     `codec:"token" json:"token"`
	Csrf    CsrfToken        `codec:"csrf" json:"csrf"`
	Pps     PassphraseStream `codec:"pps" json:"pps"`
	SigBody string           `codec:"sigBody" json:"sigBody"`
}

type DidCounterSignArg struct {
	Sig []byte `codec:"sig" json:"sig"`
}

type Kex2ProvisioneeInterface interface {
	Hello(context.Context, HelloArg) (HelloRes, error)
	DidCounterSign(context.Context, []byte) error
}

func Kex2ProvisioneeProtocol(i Kex2ProvisioneeInterface) rpc.Protocol {
	return rpc.Protocol{
		Name: "keybase.1.Kex2Provisionee",
		Methods: map[string]rpc.ServeHandlerDescription{
			"hello": {
				MakeArg: func() interface{} {
					ret := make([]HelloArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]HelloArg)
					if !ok {
						err = rpc.NewTypeError((*[]HelloArg)(nil), args)
						return
					}
					ret, err = i.Hello(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"didCounterSign": {
				MakeArg: func() interface{} {
					ret := make([]DidCounterSignArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]DidCounterSignArg)
					if !ok {
						err = rpc.NewTypeError((*[]DidCounterSignArg)(nil), args)
						return
					}
					err = i.DidCounterSign(ctx, (*typedArgs)[0].Sig)
					return
				},
				MethodType: rpc.MethodCall,
			},
		},
	}
}

type Kex2ProvisioneeClient struct {
	Cli rpc.GenericClient
}

func (c Kex2ProvisioneeClient) Hello(ctx context.Context, __arg HelloArg) (res HelloRes, err error) {
	err = c.Cli.Call(ctx, "keybase.1.Kex2Provisionee.hello", []interface{}{__arg}, &res)
	return
}

func (c Kex2ProvisioneeClient) DidCounterSign(ctx context.Context, sig []byte) (err error) {
	__arg := DidCounterSignArg{Sig: sig}
	err = c.Cli.Call(ctx, "keybase.1.Kex2Provisionee.didCounterSign", []interface{}{__arg}, nil)
	return
}
