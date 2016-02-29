package keybase1

import (
	rpc "github.com/keybase/go-framed-msgpack-rpc"
	context "golang.org/x/net/context"
)

type UpdateAction int

const (
	UpdateAction_UPDATE UpdateAction = 0
	UpdateAction_SKIP   UpdateAction = 1
	UpdateAction_SNOOZE UpdateAction = 2
	UpdateAction_CANCEL UpdateAction = 3
)

type UpdatePromptRes struct {
	Action            UpdateAction `codec:"action" json:"action"`
	AlwaysAutoInstall bool         `codec:"alwaysAutoInstall" json:"alwaysAutoInstall"`
	SnoozeUntil       Time         `codec:"snoozeUntil" json:"snoozeUntil"`
}

type UpdatePromptOptions struct {
	AlwaysAutoInstall bool `codec:"alwaysAutoInstall" json:"alwaysAutoInstall"`
}

type UpdateAppInUseAction int

const (
	UpdateAppInUseAction_CANCEL         UpdateAppInUseAction = 0
	UpdateAppInUseAction_FORCE          UpdateAppInUseAction = 1
	UpdateAppInUseAction_SNOOZE         UpdateAppInUseAction = 2
	UpdateAppInUseAction_KILL_PROCESSES UpdateAppInUseAction = 3
)

type UpdateAppInUseRes struct {
	Action UpdateAppInUseAction `codec:"action" json:"action"`
}

type UpdateQuitRes struct {
	Quit            bool   `codec:"quit" json:"quit"`
	Pid             int    `codec:"pid" json:"pid"`
	ApplicationPath string `codec:"applicationPath" json:"applicationPath"`
}

type UpdatePromptArg struct {
	SessionID int                 `codec:"sessionID" json:"sessionID"`
	Update    Update              `codec:"update" json:"update"`
	Options   UpdatePromptOptions `codec:"options" json:"options"`
}

type UpdateAppInUseArg struct {
	SessionID int       `codec:"sessionID" json:"sessionID"`
	Update    Update    `codec:"update" json:"update"`
	Processes []Process `codec:"processes" json:"processes"`
}

type UpdateQuitArg struct {
}

type UpdateUiInterface interface {
	UpdatePrompt(context.Context, UpdatePromptArg) (UpdatePromptRes, error)
	UpdateAppInUse(context.Context, UpdateAppInUseArg) (UpdateAppInUseRes, error)
	UpdateQuit(context.Context) (UpdateQuitRes, error)
}

func UpdateUiProtocol(i UpdateUiInterface) rpc.Protocol {
	return rpc.Protocol{
		Name: "keybase.1.updateUi",
		Methods: map[string]rpc.ServeHandlerDescription{
			"updatePrompt": {
				MakeArg: func() interface{} {
					ret := make([]UpdatePromptArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]UpdatePromptArg)
					if !ok {
						err = rpc.NewTypeError((*[]UpdatePromptArg)(nil), args)
						return
					}
					ret, err = i.UpdatePrompt(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"updateAppInUse": {
				MakeArg: func() interface{} {
					ret := make([]UpdateAppInUseArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]UpdateAppInUseArg)
					if !ok {
						err = rpc.NewTypeError((*[]UpdateAppInUseArg)(nil), args)
						return
					}
					ret, err = i.UpdateAppInUse(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"updateQuit": {
				MakeArg: func() interface{} {
					ret := make([]UpdateQuitArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					ret, err = i.UpdateQuit(ctx)
					return
				},
				MethodType: rpc.MethodCall,
			},
		},
	}
}

type UpdateUiClient struct {
	Cli rpc.GenericClient
}

func (c UpdateUiClient) UpdatePrompt(ctx context.Context, __arg UpdatePromptArg) (res UpdatePromptRes, err error) {
	err = c.Cli.Call(ctx, "keybase.1.updateUi.updatePrompt", []interface{}{__arg}, &res)
	return
}

func (c UpdateUiClient) UpdateAppInUse(ctx context.Context, __arg UpdateAppInUseArg) (res UpdateAppInUseRes, err error) {
	err = c.Cli.Call(ctx, "keybase.1.updateUi.updateAppInUse", []interface{}{__arg}, &res)
	return
}

func (c UpdateUiClient) UpdateQuit(ctx context.Context) (res UpdateQuitRes, err error) {
	err = c.Cli.Call(ctx, "keybase.1.updateUi.updateQuit", []interface{}{UpdateQuitArg{}}, &res)
	return
}
