package keybase1

import (
	rpc "github.com/keybase/go-framed-msgpack-rpc"
	context "golang.org/x/net/context"
)

type SaltpackSenderType int

const (
	SaltpackSenderType_NOT_TRACKED    SaltpackSenderType = 0
	SaltpackSenderType_UNKNOWN        SaltpackSenderType = 1
	SaltpackSenderType_ANONYMOUS      SaltpackSenderType = 2
	SaltpackSenderType_TRACKING_BROKE SaltpackSenderType = 3
	SaltpackSenderType_TRACKING_OK    SaltpackSenderType = 4
	SaltpackSenderType_SELF           SaltpackSenderType = 5
)

type SaltpackSender struct {
	Uid        UID                `codec:"uid" json:"uid"`
	Username   string             `codec:"username" json:"username"`
	SenderType SaltpackSenderType `codec:"senderType" json:"senderType"`
}

type SaltpackPromptForDecryptArg struct {
	SessionID int            `codec:"sessionID" json:"sessionID"`
	Sender    SaltpackSender `codec:"sender" json:"sender"`
}

type SaltpackVerifySuccessArg struct {
	SessionID  int            `codec:"sessionID" json:"sessionID"`
	SigningKID KID            `codec:"signingKID" json:"signingKID"`
	Sender     SaltpackSender `codec:"sender" json:"sender"`
}

type SaltpackUiInterface interface {
	SaltpackPromptForDecrypt(context.Context, SaltpackPromptForDecryptArg) error
	SaltpackVerifySuccess(context.Context, SaltpackVerifySuccessArg) error
}

func SaltpackUiProtocol(i SaltpackUiInterface) rpc.Protocol {
	return rpc.Protocol{
		Name: "keybase.1.saltpackUi",
		Methods: map[string]rpc.ServeHandlerDescription{
			"saltpackPromptForDecrypt": {
				MakeArg: func() interface{} {
					ret := make([]SaltpackPromptForDecryptArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]SaltpackPromptForDecryptArg)
					if !ok {
						err = rpc.NewTypeError((*[]SaltpackPromptForDecryptArg)(nil), args)
						return
					}
					err = i.SaltpackPromptForDecrypt(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"saltpackVerifySuccess": {
				MakeArg: func() interface{} {
					ret := make([]SaltpackVerifySuccessArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]SaltpackVerifySuccessArg)
					if !ok {
						err = rpc.NewTypeError((*[]SaltpackVerifySuccessArg)(nil), args)
						return
					}
					err = i.SaltpackVerifySuccess(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
		},
	}
}

type SaltpackUiClient struct {
	Cli rpc.GenericClient
}

func (c SaltpackUiClient) SaltpackPromptForDecrypt(ctx context.Context, __arg SaltpackPromptForDecryptArg) (err error) {
	err = c.Cli.Call(ctx, "keybase.1.saltpackUi.saltpackPromptForDecrypt", []interface{}{__arg}, nil)
	return
}

func (c SaltpackUiClient) SaltpackVerifySuccess(ctx context.Context, __arg SaltpackVerifySuccessArg) (err error) {
	err = c.Cli.Call(ctx, "keybase.1.saltpackUi.saltpackVerifySuccess", []interface{}{__arg}, nil)
	return
}
