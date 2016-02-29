package keybase1

import (
	rpc "github.com/keybase/go-framed-msgpack-rpc"
	context "golang.org/x/net/context"
)

type DeviceListArg struct {
	SessionID int `codec:"sessionID" json:"sessionID"`
}

type DeviceAddArg struct {
	SessionID int `codec:"sessionID" json:"sessionID"`
}

type DeviceInterface interface {
	DeviceList(context.Context, int) ([]Device, error)
	DeviceAdd(context.Context, int) error
}

func DeviceProtocol(i DeviceInterface) rpc.Protocol {
	return rpc.Protocol{
		Name: "keybase.1.device",
		Methods: map[string]rpc.ServeHandlerDescription{
			"deviceList": {
				MakeArg: func() interface{} {
					ret := make([]DeviceListArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]DeviceListArg)
					if !ok {
						err = rpc.NewTypeError((*[]DeviceListArg)(nil), args)
						return
					}
					ret, err = i.DeviceList(ctx, (*typedArgs)[0].SessionID)
					return
				},
				MethodType: rpc.MethodCall,
			},
			"deviceAdd": {
				MakeArg: func() interface{} {
					ret := make([]DeviceAddArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]DeviceAddArg)
					if !ok {
						err = rpc.NewTypeError((*[]DeviceAddArg)(nil), args)
						return
					}
					err = i.DeviceAdd(ctx, (*typedArgs)[0].SessionID)
					return
				},
				MethodType: rpc.MethodCall,
			},
		},
	}
}

type DeviceClient struct {
	Cli rpc.GenericClient
}

func (c DeviceClient) DeviceList(ctx context.Context, sessionID int) (res []Device, err error) {
	__arg := DeviceListArg{SessionID: sessionID}
	err = c.Cli.Call(ctx, "keybase.1.device.deviceList", []interface{}{__arg}, &res)
	return
}

func (c DeviceClient) DeviceAdd(ctx context.Context, sessionID int) (err error) {
	__arg := DeviceAddArg{SessionID: sessionID}
	err = c.Cli.Call(ctx, "keybase.1.device.deviceAdd", []interface{}{__arg}, nil)
	return
}
