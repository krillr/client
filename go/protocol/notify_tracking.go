package keybase1

import (
	rpc "github.com/keybase/go-framed-msgpack-rpc"
	context "golang.org/x/net/context"
)

type TrackingChangedArg struct {
	Uid      UID    `codec:"uid" json:"uid"`
	Username string `codec:"username" json:"username"`
}

type NotifyTrackingInterface interface {
	TrackingChanged(context.Context, TrackingChangedArg) error
}

func NotifyTrackingProtocol(i NotifyTrackingInterface) rpc.Protocol {
	return rpc.Protocol{
		Name: "keybase.1.NotifyTracking",
		Methods: map[string]rpc.ServeHandlerDescription{
			"trackingChanged": {
				MakeArg: func() interface{} {
					ret := make([]TrackingChangedArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]TrackingChangedArg)
					if !ok {
						err = rpc.NewTypeError((*[]TrackingChangedArg)(nil), args)
						return
					}
					err = i.TrackingChanged(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodNotify,
			},
		},
	}
}

type NotifyTrackingClient struct {
	Cli rpc.GenericClient
}

func (c NotifyTrackingClient) TrackingChanged(ctx context.Context, __arg TrackingChangedArg) (err error) {
	err = c.Cli.Notify(ctx, "keybase.1.NotifyTracking.trackingChanged", []interface{}{__arg})
	return
}
