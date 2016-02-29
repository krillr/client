package keybase1

import (
	rpc "github.com/keybase/go-framed-msgpack-rpc"
	context "golang.org/x/net/context"
)

type FirstStepResult struct {
	ValPlusTwo int `codec:"valPlusTwo" json:"valPlusTwo"`
}

type FirstStepArg struct {
	SessionID int `codec:"sessionID" json:"sessionID"`
	Val       int `codec:"val" json:"val"`
}

type SecondStepArg struct {
	SessionID int `codec:"sessionID" json:"sessionID"`
	Val       int `codec:"val" json:"val"`
}

type IncrementArg struct {
	SessionID int `codec:"sessionID" json:"sessionID"`
	Val       int `codec:"val" json:"val"`
}

type DebuggingInterface interface {
	FirstStep(context.Context, FirstStepArg) (FirstStepResult, error)
	SecondStep(context.Context, SecondStepArg) (int, error)
	Increment(context.Context, IncrementArg) (int, error)
}

func DebuggingProtocol(i DebuggingInterface) rpc.Protocol {
	return rpc.Protocol{
		Name: "keybase.1.debugging",
		Methods: map[string]rpc.ServeHandlerDescription{
			"firstStep": {
				MakeArg: func() interface{} {
					ret := make([]FirstStepArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]FirstStepArg)
					if !ok {
						err = rpc.NewTypeError((*[]FirstStepArg)(nil), args)
						return
					}
					ret, err = i.FirstStep(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"secondStep": {
				MakeArg: func() interface{} {
					ret := make([]SecondStepArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]SecondStepArg)
					if !ok {
						err = rpc.NewTypeError((*[]SecondStepArg)(nil), args)
						return
					}
					ret, err = i.SecondStep(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"increment": {
				MakeArg: func() interface{} {
					ret := make([]IncrementArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]IncrementArg)
					if !ok {
						err = rpc.NewTypeError((*[]IncrementArg)(nil), args)
						return
					}
					ret, err = i.Increment(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
		},
	}
}

type DebuggingClient struct {
	Cli rpc.GenericClient
}

func (c DebuggingClient) FirstStep(ctx context.Context, __arg FirstStepArg) (res FirstStepResult, err error) {
	err = c.Cli.Call(ctx, "keybase.1.debugging.firstStep", []interface{}{__arg}, &res)
	return
}

func (c DebuggingClient) SecondStep(ctx context.Context, __arg SecondStepArg) (res int, err error) {
	err = c.Cli.Call(ctx, "keybase.1.debugging.secondStep", []interface{}{__arg}, &res)
	return
}

func (c DebuggingClient) Increment(ctx context.Context, __arg IncrementArg) (res int, err error) {
	err = c.Cli.Call(ctx, "keybase.1.debugging.increment", []interface{}{__arg}, &res)
	return
}
