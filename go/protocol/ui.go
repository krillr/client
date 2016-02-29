package keybase1

import (
	rpc "github.com/keybase/go-framed-msgpack-rpc"
	context "golang.org/x/net/context"
)

type PromptDefault int

const (
	PromptDefault_NONE PromptDefault = 0
	PromptDefault_YES  PromptDefault = 1
	PromptDefault_NO   PromptDefault = 2
)

type PromptYesNoArg struct {
	SessionID     int           `codec:"sessionID" json:"sessionID"`
	Text          Text          `codec:"text" json:"text"`
	PromptDefault PromptDefault `codec:"promptDefault" json:"promptDefault"`
}

type UiInterface interface {
	PromptYesNo(context.Context, PromptYesNoArg) (bool, error)
}

func UiProtocol(i UiInterface) rpc.Protocol {
	return rpc.Protocol{
		Name: "keybase.1.ui",
		Methods: map[string]rpc.ServeHandlerDescription{
			"promptYesNo": {
				MakeArg: func() interface{} {
					ret := make([]PromptYesNoArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]PromptYesNoArg)
					if !ok {
						err = rpc.NewTypeError((*[]PromptYesNoArg)(nil), args)
						return
					}
					ret, err = i.PromptYesNo(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
		},
	}
}

type UiClient struct {
	Cli rpc.GenericClient
}

func (c UiClient) PromptYesNo(ctx context.Context, __arg PromptYesNoArg) (res bool, err error) {
	err = c.Cli.Call(ctx, "keybase.1.ui.promptYesNo", []interface{}{__arg}, &res)
	return
}
