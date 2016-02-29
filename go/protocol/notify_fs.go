package keybase1

import (
	rpc "github.com/keybase/go-framed-msgpack-rpc"
	context "golang.org/x/net/context"
)

type FSActivityArg struct {
	Notification FSNotification `codec:"notification" json:"notification"`
}

type NotifyFSInterface interface {
	FSActivity(context.Context, FSNotification) error
}

func NotifyFSProtocol(i NotifyFSInterface) rpc.Protocol {
	return rpc.Protocol{
		Name: "keybase.1.NotifyFS",
		Methods: map[string]rpc.ServeHandlerDescription{
			"FSActivity": {
				MakeArg: func() interface{} {
					ret := make([]FSActivityArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]FSActivityArg)
					if !ok {
						err = rpc.NewTypeError((*[]FSActivityArg)(nil), args)
						return
					}
					err = i.FSActivity(ctx, (*typedArgs)[0].Notification)
					return
				},
				MethodType: rpc.MethodNotify,
			},
		},
	}
}

type NotifyFSClient struct {
	Cli rpc.GenericClient
}

func (c NotifyFSClient) FSActivity(ctx context.Context, notification FSNotification) (err error) {
	__arg := FSActivityArg{Notification: notification}
	err = c.Cli.Notify(ctx, "keybase.1.NotifyFS.FSActivity", []interface{}{__arg})
	return
}
