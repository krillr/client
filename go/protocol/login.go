package keybase1

import (
	rpc "github.com/keybase/go-framed-msgpack-rpc"
	context "golang.org/x/net/context"
)

type ConfiguredAccount struct {
	Username        string `codec:"username" json:"username"`
	HasStoredSecret bool   `codec:"hasStoredSecret" json:"hasStoredSecret"`
}

type GetConfiguredAccountsArg struct {
	SessionID int `codec:"sessionID" json:"sessionID"`
}

type LoginArg struct {
	SessionID  int        `codec:"sessionID" json:"sessionID"`
	DeviceType string     `codec:"deviceType" json:"deviceType"`
	Username   string     `codec:"username" json:"username"`
	ClientType ClientType `codec:"clientType" json:"clientType"`
}

type ClearStoredSecretArg struct {
	SessionID int    `codec:"sessionID" json:"sessionID"`
	Username  string `codec:"username" json:"username"`
}

type LogoutArg struct {
	SessionID int `codec:"sessionID" json:"sessionID"`
}

type DeprovisionArg struct {
	SessionID int    `codec:"sessionID" json:"sessionID"`
	Username  string `codec:"username" json:"username"`
	DoRevoke  bool   `codec:"doRevoke" json:"doRevoke"`
}

type RecoverAccountFromEmailAddressArg struct {
	Email string `codec:"email" json:"email"`
}

type PaperKeyArg struct {
	SessionID int `codec:"sessionID" json:"sessionID"`
}

type UnlockArg struct {
	SessionID int `codec:"sessionID" json:"sessionID"`
}

type UnlockWithPassphraseArg struct {
	SessionID  int    `codec:"sessionID" json:"sessionID"`
	Passphrase string `codec:"passphrase" json:"passphrase"`
}

type LoginInterface interface {
	GetConfiguredAccounts(context.Context, int) ([]ConfiguredAccount, error)
	Login(context.Context, LoginArg) error
	ClearStoredSecret(context.Context, ClearStoredSecretArg) error
	Logout(context.Context, int) error
	Deprovision(context.Context, DeprovisionArg) error
	RecoverAccountFromEmailAddress(context.Context, string) error
	PaperKey(context.Context, int) error
	Unlock(context.Context, int) error
	UnlockWithPassphrase(context.Context, UnlockWithPassphraseArg) error
}

func LoginProtocol(i LoginInterface) rpc.Protocol {
	return rpc.Protocol{
		Name: "keybase.1.login",
		Methods: map[string]rpc.ServeHandlerDescription{
			"getConfiguredAccounts": {
				MakeArg: func() interface{} {
					ret := make([]GetConfiguredAccountsArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]GetConfiguredAccountsArg)
					if !ok {
						err = rpc.NewTypeError((*[]GetConfiguredAccountsArg)(nil), args)
						return
					}
					ret, err = i.GetConfiguredAccounts(ctx, (*typedArgs)[0].SessionID)
					return
				},
				MethodType: rpc.MethodCall,
			},
			"login": {
				MakeArg: func() interface{} {
					ret := make([]LoginArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]LoginArg)
					if !ok {
						err = rpc.NewTypeError((*[]LoginArg)(nil), args)
						return
					}
					err = i.Login(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"clearStoredSecret": {
				MakeArg: func() interface{} {
					ret := make([]ClearStoredSecretArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]ClearStoredSecretArg)
					if !ok {
						err = rpc.NewTypeError((*[]ClearStoredSecretArg)(nil), args)
						return
					}
					err = i.ClearStoredSecret(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"logout": {
				MakeArg: func() interface{} {
					ret := make([]LogoutArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]LogoutArg)
					if !ok {
						err = rpc.NewTypeError((*[]LogoutArg)(nil), args)
						return
					}
					err = i.Logout(ctx, (*typedArgs)[0].SessionID)
					return
				},
				MethodType: rpc.MethodCall,
			},
			"deprovision": {
				MakeArg: func() interface{} {
					ret := make([]DeprovisionArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]DeprovisionArg)
					if !ok {
						err = rpc.NewTypeError((*[]DeprovisionArg)(nil), args)
						return
					}
					err = i.Deprovision(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"recoverAccountFromEmailAddress": {
				MakeArg: func() interface{} {
					ret := make([]RecoverAccountFromEmailAddressArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]RecoverAccountFromEmailAddressArg)
					if !ok {
						err = rpc.NewTypeError((*[]RecoverAccountFromEmailAddressArg)(nil), args)
						return
					}
					err = i.RecoverAccountFromEmailAddress(ctx, (*typedArgs)[0].Email)
					return
				},
				MethodType: rpc.MethodCall,
			},
			"paperKey": {
				MakeArg: func() interface{} {
					ret := make([]PaperKeyArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]PaperKeyArg)
					if !ok {
						err = rpc.NewTypeError((*[]PaperKeyArg)(nil), args)
						return
					}
					err = i.PaperKey(ctx, (*typedArgs)[0].SessionID)
					return
				},
				MethodType: rpc.MethodCall,
			},
			"unlock": {
				MakeArg: func() interface{} {
					ret := make([]UnlockArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]UnlockArg)
					if !ok {
						err = rpc.NewTypeError((*[]UnlockArg)(nil), args)
						return
					}
					err = i.Unlock(ctx, (*typedArgs)[0].SessionID)
					return
				},
				MethodType: rpc.MethodCall,
			},
			"unlockWithPassphrase": {
				MakeArg: func() interface{} {
					ret := make([]UnlockWithPassphraseArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]UnlockWithPassphraseArg)
					if !ok {
						err = rpc.NewTypeError((*[]UnlockWithPassphraseArg)(nil), args)
						return
					}
					err = i.UnlockWithPassphrase(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
		},
	}
}

type LoginClient struct {
	Cli rpc.GenericClient
}

func (c LoginClient) GetConfiguredAccounts(ctx context.Context, sessionID int) (res []ConfiguredAccount, err error) {
	__arg := GetConfiguredAccountsArg{SessionID: sessionID}
	err = c.Cli.Call(ctx, "keybase.1.login.getConfiguredAccounts", []interface{}{__arg}, &res)
	return
}

func (c LoginClient) Login(ctx context.Context, __arg LoginArg) (err error) {
	err = c.Cli.Call(ctx, "keybase.1.login.login", []interface{}{__arg}, nil)
	return
}

func (c LoginClient) ClearStoredSecret(ctx context.Context, __arg ClearStoredSecretArg) (err error) {
	err = c.Cli.Call(ctx, "keybase.1.login.clearStoredSecret", []interface{}{__arg}, nil)
	return
}

func (c LoginClient) Logout(ctx context.Context, sessionID int) (err error) {
	__arg := LogoutArg{SessionID: sessionID}
	err = c.Cli.Call(ctx, "keybase.1.login.logout", []interface{}{__arg}, nil)
	return
}

func (c LoginClient) Deprovision(ctx context.Context, __arg DeprovisionArg) (err error) {
	err = c.Cli.Call(ctx, "keybase.1.login.deprovision", []interface{}{__arg}, nil)
	return
}

func (c LoginClient) RecoverAccountFromEmailAddress(ctx context.Context, email string) (err error) {
	__arg := RecoverAccountFromEmailAddressArg{Email: email}
	err = c.Cli.Call(ctx, "keybase.1.login.recoverAccountFromEmailAddress", []interface{}{__arg}, nil)
	return
}

func (c LoginClient) PaperKey(ctx context.Context, sessionID int) (err error) {
	__arg := PaperKeyArg{SessionID: sessionID}
	err = c.Cli.Call(ctx, "keybase.1.login.paperKey", []interface{}{__arg}, nil)
	return
}

func (c LoginClient) Unlock(ctx context.Context, sessionID int) (err error) {
	__arg := UnlockArg{SessionID: sessionID}
	err = c.Cli.Call(ctx, "keybase.1.login.unlock", []interface{}{__arg}, nil)
	return
}

func (c LoginClient) UnlockWithPassphrase(ctx context.Context, __arg UnlockWithPassphraseArg) (err error) {
	err = c.Cli.Call(ctx, "keybase.1.login.unlockWithPassphrase", []interface{}{__arg}, nil)
	return
}
