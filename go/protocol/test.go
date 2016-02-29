package keybase1

import (
	rpc "github.com/keybase/go-framed-msgpack-rpc"
	context "golang.org/x/net/context"
)

type Test struct {
	Reply string `codec:"reply" json:"reply"`
}

type TestArg struct {
	SessionID int    `codec:"sessionID" json:"sessionID"`
	Name      string `codec:"name" json:"name"`
}

type TestCallbackArg struct {
	SessionID int    `codec:"sessionID" json:"sessionID"`
	Name      string `codec:"name" json:"name"`
}

type PanicArg struct {
	Message string `codec:"message" json:"message"`
}

type TestInterface interface {
	Test(context.Context, TestArg) (Test, error)
	TestCallback(context.Context, TestCallbackArg) (string, error)
	Panic(context.Context, string) error
}

func TestProtocol(i TestInterface) rpc.Protocol {
	return rpc.Protocol{
		Name: "keybase.1.test",
		Methods: map[string]rpc.ServeHandlerDescription{
			"test": {
				MakeArg: func() interface{} {
					ret := make([]TestArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]TestArg)
					if !ok {
						err = rpc.NewTypeError((*[]TestArg)(nil), args)
						return
					}
					ret, err = i.Test(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"testCallback": {
				MakeArg: func() interface{} {
					ret := make([]TestCallbackArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]TestCallbackArg)
					if !ok {
						err = rpc.NewTypeError((*[]TestCallbackArg)(nil), args)
						return
					}
					ret, err = i.TestCallback(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"panic": {
				MakeArg: func() interface{} {
					ret := make([]PanicArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]PanicArg)
					if !ok {
						err = rpc.NewTypeError((*[]PanicArg)(nil), args)
						return
					}
					err = i.Panic(ctx, (*typedArgs)[0].Message)
					return
				},
				MethodType: rpc.MethodCall,
			},
		},
	}
}

type TestClient struct {
	Cli rpc.GenericClient
}

func (c TestClient) Test(ctx context.Context, __arg TestArg) (res Test, err error) {
	err = c.Cli.Call(ctx, "keybase.1.test.test", []interface{}{__arg}, &res)
	return
}

func (c TestClient) TestCallback(ctx context.Context, __arg TestCallbackArg) (res string, err error) {
	err = c.Cli.Call(ctx, "keybase.1.test.testCallback", []interface{}{__arg}, &res)
	return
}

func (c TestClient) Panic(ctx context.Context, message string) (err error) {
	__arg := PanicArg{Message: message}
	err = c.Cli.Call(ctx, "keybase.1.test.panic", []interface{}{__arg}, nil)
	return
}
