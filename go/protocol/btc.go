package keybase1

import (
	rpc "github.com/keybase/go-framed-msgpack-rpc"
	context "golang.org/x/net/context"
)

type RegisterBTCArg struct {
	SessionID int    `codec:"sessionID" json:"sessionID"`
	Address   string `codec:"address" json:"address"`
	Force     bool   `codec:"force" json:"force"`
}

type BTCInterface interface {
	RegisterBTC(context.Context, RegisterBTCArg) error
}

func BTCProtocol(i BTCInterface) rpc.Protocol {
	return rpc.Protocol{
		Name: "keybase.1.BTC",
		Methods: map[string]rpc.ServeHandlerDescription{
			"registerBTC": {
				MakeArg: func() interface{} {
					ret := make([]RegisterBTCArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]RegisterBTCArg)
					if !ok {
						err = rpc.NewTypeError((*[]RegisterBTCArg)(nil), args)
						return
					}
					err = i.RegisterBTC(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
		},
	}
}

type BTCClient struct {
	Cli rpc.GenericClient
}

func (c BTCClient) RegisterBTC(ctx context.Context, __arg RegisterBTCArg) (err error) {
	err = c.Cli.Call(ctx, "keybase.1.BTC.registerBTC", []interface{}{__arg}, nil)
	return
}
