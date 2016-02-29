package keybase1

import (
	rpc "github.com/keybase/go-framed-msgpack-rpc"
	context "golang.org/x/net/context"
)

type RegisterIdentifyUIArg struct {
}

type RegisterSecretUIArg struct {
}

type RegisterUpdateUIArg struct {
}

type DelegateUiCtlInterface interface {
	RegisterIdentifyUI(context.Context) error
	RegisterSecretUI(context.Context) error
	RegisterUpdateUI(context.Context) error
}

func DelegateUiCtlProtocol(i DelegateUiCtlInterface) rpc.Protocol {
	return rpc.Protocol{
		Name: "keybase.1.delegateUiCtl",
		Methods: map[string]rpc.ServeHandlerDescription{
			"registerIdentifyUI": {
				MakeArg: func() interface{} {
					ret := make([]RegisterIdentifyUIArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					err = i.RegisterIdentifyUI(ctx)
					return
				},
				MethodType: rpc.MethodCall,
			},
			"registerSecretUI": {
				MakeArg: func() interface{} {
					ret := make([]RegisterSecretUIArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					err = i.RegisterSecretUI(ctx)
					return
				},
				MethodType: rpc.MethodCall,
			},
			"registerUpdateUI": {
				MakeArg: func() interface{} {
					ret := make([]RegisterUpdateUIArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					err = i.RegisterUpdateUI(ctx)
					return
				},
				MethodType: rpc.MethodCall,
			},
		},
	}
}

type DelegateUiCtlClient struct {
	Cli rpc.GenericClient
}

func (c DelegateUiCtlClient) RegisterIdentifyUI(ctx context.Context) (err error) {
	err = c.Cli.Call(ctx, "keybase.1.delegateUiCtl.registerIdentifyUI", []interface{}{RegisterIdentifyUIArg{}}, nil)
	return
}

func (c DelegateUiCtlClient) RegisterSecretUI(ctx context.Context) (err error) {
	err = c.Cli.Call(ctx, "keybase.1.delegateUiCtl.registerSecretUI", []interface{}{RegisterSecretUIArg{}}, nil)
	return
}

func (c DelegateUiCtlClient) RegisterUpdateUI(ctx context.Context) (err error) {
	err = c.Cli.Call(ctx, "keybase.1.delegateUiCtl.registerUpdateUI", []interface{}{RegisterUpdateUIArg{}}, nil)
	return
}
