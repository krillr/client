package keybase1

import (
	rpc "github.com/keybase/go-framed-msgpack-rpc"
	context "golang.org/x/net/context"
)

type FSEventArg struct {
	Event FSNotification `codec:"event" json:"event"`
}

type KbfsInterface interface {
	FSEvent(context.Context, FSNotification) error
}

func KbfsProtocol(i KbfsInterface) rpc.Protocol {
	return rpc.Protocol{
		Name: "keybase.1.kbfs",
		Methods: map[string]rpc.ServeHandlerDescription{
			"FSEvent": {
				MakeArg: func() interface{} {
					ret := make([]FSEventArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]FSEventArg)
					if !ok {
						err = rpc.NewTypeError((*[]FSEventArg)(nil), args)
						return
					}
					err = i.FSEvent(ctx, (*typedArgs)[0].Event)
					return
				},
				MethodType: rpc.MethodCall,
			},
		},
	}
}

type KbfsClient struct {
	Cli rpc.GenericClient
}

func (c KbfsClient) FSEvent(ctx context.Context, event FSNotification) (err error) {
	__arg := FSEventArg{Event: event}
	err = c.Cli.Call(ctx, "keybase.1.kbfs.FSEvent", []interface{}{__arg}, nil)
	return
}
