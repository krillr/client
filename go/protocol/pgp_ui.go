package keybase1

import (
	rpc "github.com/keybase/go-framed-msgpack-rpc"
	context "golang.org/x/net/context"
)

type OutputSignatureSuccessArg struct {
	SessionID   int    `codec:"sessionID" json:"sessionID"`
	Fingerprint string `codec:"fingerprint" json:"fingerprint"`
	Username    string `codec:"username" json:"username"`
	SignedAt    Time   `codec:"signedAt" json:"signedAt"`
}

type PGPUiInterface interface {
	OutputSignatureSuccess(context.Context, OutputSignatureSuccessArg) error
}

func PGPUiProtocol(i PGPUiInterface) rpc.Protocol {
	return rpc.Protocol{
		Name: "keybase.1.pgpUi",
		Methods: map[string]rpc.ServeHandlerDescription{
			"outputSignatureSuccess": {
				MakeArg: func() interface{} {
					ret := make([]OutputSignatureSuccessArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]OutputSignatureSuccessArg)
					if !ok {
						err = rpc.NewTypeError((*[]OutputSignatureSuccessArg)(nil), args)
						return
					}
					err = i.OutputSignatureSuccess(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
		},
	}
}

type PGPUiClient struct {
	Cli rpc.GenericClient
}

func (c PGPUiClient) OutputSignatureSuccess(ctx context.Context, __arg OutputSignatureSuccessArg) (err error) {
	err = c.Cli.Call(ctx, "keybase.1.pgpUi.outputSignatureSuccess", []interface{}{__arg}, nil)
	return
}
