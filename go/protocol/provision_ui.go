package keybase1

import (
	rpc "github.com/keybase/go-framed-msgpack-rpc"
	context "golang.org/x/net/context"
)

type ProvisionMethod int

const (
	ProvisionMethod_DEVICE     ProvisionMethod = 0
	ProvisionMethod_PAPER_KEY  ProvisionMethod = 1
	ProvisionMethod_PASSPHRASE ProvisionMethod = 2
	ProvisionMethod_GPG_IMPORT ProvisionMethod = 3
	ProvisionMethod_GPG_SIGN   ProvisionMethod = 4
)

type DeviceType int

const (
	DeviceType_DESKTOP DeviceType = 0
	DeviceType_MOBILE  DeviceType = 1
)

type ChooseType int

const (
	ChooseType_EXISTING_DEVICE ChooseType = 0
	ChooseType_NEW_DEVICE      ChooseType = 1
)

type SecretResponse struct {
	Secret []byte `codec:"secret" json:"secret"`
	Phrase string `codec:"phrase" json:"phrase"`
}

type ChooseProvisioningMethodArg struct {
	SessionID int  `codec:"sessionID" json:"sessionID"`
	GpgOption bool `codec:"gpgOption" json:"gpgOption"`
}

type ChooseDeviceTypeArg struct {
	SessionID int        `codec:"sessionID" json:"sessionID"`
	Kind      ChooseType `codec:"kind" json:"kind"`
}

type DisplayAndPromptSecretArg struct {
	SessionID       int        `codec:"sessionID" json:"sessionID"`
	Secret          []byte     `codec:"secret" json:"secret"`
	Phrase          string     `codec:"phrase" json:"phrase"`
	OtherDeviceType DeviceType `codec:"otherDeviceType" json:"otherDeviceType"`
}

type DisplaySecretExchangedArg struct {
	SessionID int `codec:"sessionID" json:"sessionID"`
}

type PromptNewDeviceNameArg struct {
	SessionID       int      `codec:"sessionID" json:"sessionID"`
	ExistingDevices []string `codec:"existingDevices" json:"existingDevices"`
	ErrorMessage    string   `codec:"errorMessage" json:"errorMessage"`
}

type ProvisioneeSuccessArg struct {
	SessionID  int    `codec:"sessionID" json:"sessionID"`
	Username   string `codec:"username" json:"username"`
	DeviceName string `codec:"deviceName" json:"deviceName"`
}

type ProvisionerSuccessArg struct {
	SessionID  int    `codec:"sessionID" json:"sessionID"`
	DeviceName string `codec:"deviceName" json:"deviceName"`
	DeviceType string `codec:"deviceType" json:"deviceType"`
}

type ProvisionUiInterface interface {
	ChooseProvisioningMethod(context.Context, ChooseProvisioningMethodArg) (ProvisionMethod, error)
	ChooseDeviceType(context.Context, ChooseDeviceTypeArg) (DeviceType, error)
	DisplayAndPromptSecret(context.Context, DisplayAndPromptSecretArg) (SecretResponse, error)
	DisplaySecretExchanged(context.Context, int) error
	PromptNewDeviceName(context.Context, PromptNewDeviceNameArg) (string, error)
	ProvisioneeSuccess(context.Context, ProvisioneeSuccessArg) error
	ProvisionerSuccess(context.Context, ProvisionerSuccessArg) error
}

func ProvisionUiProtocol(i ProvisionUiInterface) rpc.Protocol {
	return rpc.Protocol{
		Name: "keybase.1.provisionUi",
		Methods: map[string]rpc.ServeHandlerDescription{
			"chooseProvisioningMethod": {
				MakeArg: func() interface{} {
					ret := make([]ChooseProvisioningMethodArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]ChooseProvisioningMethodArg)
					if !ok {
						err = rpc.NewTypeError((*[]ChooseProvisioningMethodArg)(nil), args)
						return
					}
					ret, err = i.ChooseProvisioningMethod(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"chooseDeviceType": {
				MakeArg: func() interface{} {
					ret := make([]ChooseDeviceTypeArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]ChooseDeviceTypeArg)
					if !ok {
						err = rpc.NewTypeError((*[]ChooseDeviceTypeArg)(nil), args)
						return
					}
					ret, err = i.ChooseDeviceType(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"DisplayAndPromptSecret": {
				MakeArg: func() interface{} {
					ret := make([]DisplayAndPromptSecretArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]DisplayAndPromptSecretArg)
					if !ok {
						err = rpc.NewTypeError((*[]DisplayAndPromptSecretArg)(nil), args)
						return
					}
					ret, err = i.DisplayAndPromptSecret(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"DisplaySecretExchanged": {
				MakeArg: func() interface{} {
					ret := make([]DisplaySecretExchangedArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]DisplaySecretExchangedArg)
					if !ok {
						err = rpc.NewTypeError((*[]DisplaySecretExchangedArg)(nil), args)
						return
					}
					err = i.DisplaySecretExchanged(ctx, (*typedArgs)[0].SessionID)
					return
				},
				MethodType: rpc.MethodCall,
			},
			"PromptNewDeviceName": {
				MakeArg: func() interface{} {
					ret := make([]PromptNewDeviceNameArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]PromptNewDeviceNameArg)
					if !ok {
						err = rpc.NewTypeError((*[]PromptNewDeviceNameArg)(nil), args)
						return
					}
					ret, err = i.PromptNewDeviceName(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"ProvisioneeSuccess": {
				MakeArg: func() interface{} {
					ret := make([]ProvisioneeSuccessArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]ProvisioneeSuccessArg)
					if !ok {
						err = rpc.NewTypeError((*[]ProvisioneeSuccessArg)(nil), args)
						return
					}
					err = i.ProvisioneeSuccess(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"ProvisionerSuccess": {
				MakeArg: func() interface{} {
					ret := make([]ProvisionerSuccessArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]ProvisionerSuccessArg)
					if !ok {
						err = rpc.NewTypeError((*[]ProvisionerSuccessArg)(nil), args)
						return
					}
					err = i.ProvisionerSuccess(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
		},
	}
}

type ProvisionUiClient struct {
	Cli rpc.GenericClient
}

func (c ProvisionUiClient) ChooseProvisioningMethod(ctx context.Context, __arg ChooseProvisioningMethodArg) (res ProvisionMethod, err error) {
	err = c.Cli.Call(ctx, "keybase.1.provisionUi.chooseProvisioningMethod", []interface{}{__arg}, &res)
	return
}

func (c ProvisionUiClient) ChooseDeviceType(ctx context.Context, __arg ChooseDeviceTypeArg) (res DeviceType, err error) {
	err = c.Cli.Call(ctx, "keybase.1.provisionUi.chooseDeviceType", []interface{}{__arg}, &res)
	return
}

func (c ProvisionUiClient) DisplayAndPromptSecret(ctx context.Context, __arg DisplayAndPromptSecretArg) (res SecretResponse, err error) {
	err = c.Cli.Call(ctx, "keybase.1.provisionUi.DisplayAndPromptSecret", []interface{}{__arg}, &res)
	return
}

func (c ProvisionUiClient) DisplaySecretExchanged(ctx context.Context, sessionID int) (err error) {
	__arg := DisplaySecretExchangedArg{SessionID: sessionID}
	err = c.Cli.Call(ctx, "keybase.1.provisionUi.DisplaySecretExchanged", []interface{}{__arg}, nil)
	return
}

func (c ProvisionUiClient) PromptNewDeviceName(ctx context.Context, __arg PromptNewDeviceNameArg) (res string, err error) {
	err = c.Cli.Call(ctx, "keybase.1.provisionUi.PromptNewDeviceName", []interface{}{__arg}, &res)
	return
}

func (c ProvisionUiClient) ProvisioneeSuccess(ctx context.Context, __arg ProvisioneeSuccessArg) (err error) {
	err = c.Cli.Call(ctx, "keybase.1.provisionUi.ProvisioneeSuccess", []interface{}{__arg}, nil)
	return
}

func (c ProvisionUiClient) ProvisionerSuccess(ctx context.Context, __arg ProvisionerSuccessArg) (err error) {
	err = c.Cli.Call(ctx, "keybase.1.provisionUi.ProvisionerSuccess", []interface{}{__arg}, nil)
	return
}
