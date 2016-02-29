package keybase1

import (
	rpc "github.com/keybase/go-framed-msgpack-rpc"
	context "golang.org/x/net/context"
)

type CheckProofStatus struct {
	Found     bool        `codec:"found" json:"found"`
	Status    ProofStatus `codec:"status" json:"status"`
	ProofText string      `codec:"proofText" json:"proofText"`
}

type StartProofResult struct {
	SigID SigID `codec:"sigID" json:"sigID"`
}

type StartProofArg struct {
	SessionID    int    `codec:"sessionID" json:"sessionID"`
	Service      string `codec:"service" json:"service"`
	Username     string `codec:"username" json:"username"`
	Force        bool   `codec:"force" json:"force"`
	PromptPosted bool   `codec:"promptPosted" json:"promptPosted"`
}

type CheckProofArg struct {
	SessionID int   `codec:"sessionID" json:"sessionID"`
	SigID     SigID `codec:"sigID" json:"sigID"`
}

type ProveInterface interface {
	StartProof(context.Context, StartProofArg) (StartProofResult, error)
	CheckProof(context.Context, CheckProofArg) (CheckProofStatus, error)
}

func ProveProtocol(i ProveInterface) rpc.Protocol {
	return rpc.Protocol{
		Name: "keybase.1.prove",
		Methods: map[string]rpc.ServeHandlerDescription{
			"startProof": {
				MakeArg: func() interface{} {
					ret := make([]StartProofArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]StartProofArg)
					if !ok {
						err = rpc.NewTypeError((*[]StartProofArg)(nil), args)
						return
					}
					ret, err = i.StartProof(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"checkProof": {
				MakeArg: func() interface{} {
					ret := make([]CheckProofArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]CheckProofArg)
					if !ok {
						err = rpc.NewTypeError((*[]CheckProofArg)(nil), args)
						return
					}
					ret, err = i.CheckProof(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
		},
	}
}

type ProveClient struct {
	Cli rpc.GenericClient
}

func (c ProveClient) StartProof(ctx context.Context, __arg StartProofArg) (res StartProofResult, err error) {
	err = c.Cli.Call(ctx, "keybase.1.prove.startProof", []interface{}{__arg}, &res)
	return
}

func (c ProveClient) CheckProof(ctx context.Context, __arg CheckProofArg) (res CheckProofStatus, err error) {
	err = c.Cli.Call(ctx, "keybase.1.prove.checkProof", []interface{}{__arg}, &res)
	return
}
