package keybase1

import (
	rpc "github.com/keybase/go-framed-msgpack-rpc"
	context "golang.org/x/net/context"
)

type GetCurrentStatusRes struct {
	Configured     bool  `codec:"configured" json:"configured"`
	Registered     bool  `codec:"registered" json:"registered"`
	LoggedIn       bool  `codec:"loggedIn" json:"loggedIn"`
	SessionIsValid bool  `codec:"sessionIsValid" json:"sessionIsValid"`
	User           *User `codec:"user,omitempty" json:"user,omitempty"`
}

type SessionStatus struct {
	SessionFor string `codec:"SessionFor" json:"SessionFor"`
	Loaded     bool   `codec:"Loaded" json:"Loaded"`
	Cleared    bool   `codec:"Cleared" json:"Cleared"`
	SaltOnly   bool   `codec:"SaltOnly" json:"SaltOnly"`
	Expired    bool   `codec:"Expired" json:"Expired"`
}

type ClientDetails struct {
	Pid        int        `codec:"pid" json:"pid"`
	ClientType ClientType `codec:"clientType" json:"clientType"`
	Argv       []string   `codec:"argv" json:"argv"`
	Desc       string     `codec:"desc" json:"desc"`
	Version    string     `codec:"version" json:"version"`
}

type PlatformInfo struct {
	Os        string `codec:"os" json:"os"`
	Arch      string `codec:"arch" json:"arch"`
	GoVersion string `codec:"goVersion" json:"goVersion"`
}

type ExtendedStatus struct {
	Standalone             bool            `codec:"standalone" json:"standalone"`
	PassphraseStreamCached bool            `codec:"passphraseStreamCached" json:"passphraseStreamCached"`
	Device                 *Device         `codec:"device,omitempty" json:"device,omitempty"`
	LogDir                 string          `codec:"logDir" json:"logDir"`
	Session                *SessionStatus  `codec:"session,omitempty" json:"session,omitempty"`
	DefaultUsername        string          `codec:"defaultUsername" json:"defaultUsername"`
	ProvisionedUsernames   []string        `codec:"provisionedUsernames" json:"provisionedUsernames"`
	Clients                []ClientDetails `codec:"Clients" json:"Clients"`
	PlatformInfo           PlatformInfo    `codec:"platformInfo" json:"platformInfo"`
}

type ForkType int

const (
	ForkType_NONE     ForkType = 0
	ForkType_AUTO     ForkType = 1
	ForkType_WATCHDOG ForkType = 2
	ForkType_LAUNCHD  ForkType = 3
)

type Config struct {
	ServerURI    string   `codec:"serverURI" json:"serverURI"`
	SocketFile   string   `codec:"socketFile" json:"socketFile"`
	Label        string   `codec:"label" json:"label"`
	RunMode      string   `codec:"runMode" json:"runMode"`
	GpgExists    bool     `codec:"gpgExists" json:"gpgExists"`
	GpgPath      string   `codec:"gpgPath" json:"gpgPath"`
	Version      string   `codec:"version" json:"version"`
	Path         string   `codec:"path" json:"path"`
	ConfigPath   string   `codec:"configPath" json:"configPath"`
	VersionShort string   `codec:"versionShort" json:"versionShort"`
	VersionFull  string   `codec:"versionFull" json:"versionFull"`
	IsAutoForked bool     `codec:"isAutoForked" json:"isAutoForked"`
	ForkType     ForkType `codec:"forkType" json:"forkType"`
}

type ConfigValue struct {
	IsNull bool    `codec:"isNull" json:"isNull"`
	B      *bool   `codec:"b,omitempty" json:"b,omitempty"`
	I      *int    `codec:"i,omitempty" json:"i,omitempty"`
	S      *string `codec:"s,omitempty" json:"s,omitempty"`
	O      *string `codec:"o,omitempty" json:"o,omitempty"`
}

type GetCurrentStatusArg struct {
	SessionID int `codec:"sessionID" json:"sessionID"`
}

type GetExtendedStatusArg struct {
	SessionID int `codec:"sessionID" json:"sessionID"`
}

type GetConfigArg struct {
	SessionID int `codec:"sessionID" json:"sessionID"`
}

type SetUserConfigArg struct {
	SessionID int    `codec:"sessionID" json:"sessionID"`
	Username  string `codec:"username" json:"username"`
	Key       string `codec:"key" json:"key"`
	Value     string `codec:"value" json:"value"`
}

type SetPathArg struct {
	SessionID int    `codec:"sessionID" json:"sessionID"`
	Path      string `codec:"path" json:"path"`
}

type HelloIAmArg struct {
	Details ClientDetails `codec:"details" json:"details"`
}

type SetValueArg struct {
	Path  string      `codec:"path" json:"path"`
	Value ConfigValue `codec:"value" json:"value"`
}

type ClearValueArg struct {
	Path string `codec:"path" json:"path"`
}

type GetValueArg struct {
	Path string `codec:"path" json:"path"`
}

type ConfigInterface interface {
	GetCurrentStatus(context.Context, int) (GetCurrentStatusRes, error)
	GetExtendedStatus(context.Context, int) (ExtendedStatus, error)
	GetConfig(context.Context, int) (Config, error)
	SetUserConfig(context.Context, SetUserConfigArg) error
	SetPath(context.Context, SetPathArg) error
	HelloIAm(context.Context, ClientDetails) error
	SetValue(context.Context, SetValueArg) error
	ClearValue(context.Context, string) error
	GetValue(context.Context, string) (ConfigValue, error)
}

func ConfigProtocol(i ConfigInterface) rpc.Protocol {
	return rpc.Protocol{
		Name: "keybase.1.config",
		Methods: map[string]rpc.ServeHandlerDescription{
			"getCurrentStatus": {
				MakeArg: func() interface{} {
					ret := make([]GetCurrentStatusArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]GetCurrentStatusArg)
					if !ok {
						err = rpc.NewTypeError((*[]GetCurrentStatusArg)(nil), args)
						return
					}
					ret, err = i.GetCurrentStatus(ctx, (*typedArgs)[0].SessionID)
					return
				},
				MethodType: rpc.MethodCall,
			},
			"getExtendedStatus": {
				MakeArg: func() interface{} {
					ret := make([]GetExtendedStatusArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]GetExtendedStatusArg)
					if !ok {
						err = rpc.NewTypeError((*[]GetExtendedStatusArg)(nil), args)
						return
					}
					ret, err = i.GetExtendedStatus(ctx, (*typedArgs)[0].SessionID)
					return
				},
				MethodType: rpc.MethodCall,
			},
			"getConfig": {
				MakeArg: func() interface{} {
					ret := make([]GetConfigArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]GetConfigArg)
					if !ok {
						err = rpc.NewTypeError((*[]GetConfigArg)(nil), args)
						return
					}
					ret, err = i.GetConfig(ctx, (*typedArgs)[0].SessionID)
					return
				},
				MethodType: rpc.MethodCall,
			},
			"setUserConfig": {
				MakeArg: func() interface{} {
					ret := make([]SetUserConfigArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]SetUserConfigArg)
					if !ok {
						err = rpc.NewTypeError((*[]SetUserConfigArg)(nil), args)
						return
					}
					err = i.SetUserConfig(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"setPath": {
				MakeArg: func() interface{} {
					ret := make([]SetPathArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]SetPathArg)
					if !ok {
						err = rpc.NewTypeError((*[]SetPathArg)(nil), args)
						return
					}
					err = i.SetPath(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"helloIAm": {
				MakeArg: func() interface{} {
					ret := make([]HelloIAmArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]HelloIAmArg)
					if !ok {
						err = rpc.NewTypeError((*[]HelloIAmArg)(nil), args)
						return
					}
					err = i.HelloIAm(ctx, (*typedArgs)[0].Details)
					return
				},
				MethodType: rpc.MethodCall,
			},
			"setValue": {
				MakeArg: func() interface{} {
					ret := make([]SetValueArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]SetValueArg)
					if !ok {
						err = rpc.NewTypeError((*[]SetValueArg)(nil), args)
						return
					}
					err = i.SetValue(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"clearValue": {
				MakeArg: func() interface{} {
					ret := make([]ClearValueArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]ClearValueArg)
					if !ok {
						err = rpc.NewTypeError((*[]ClearValueArg)(nil), args)
						return
					}
					err = i.ClearValue(ctx, (*typedArgs)[0].Path)
					return
				},
				MethodType: rpc.MethodCall,
			},
			"getValue": {
				MakeArg: func() interface{} {
					ret := make([]GetValueArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]GetValueArg)
					if !ok {
						err = rpc.NewTypeError((*[]GetValueArg)(nil), args)
						return
					}
					ret, err = i.GetValue(ctx, (*typedArgs)[0].Path)
					return
				},
				MethodType: rpc.MethodCall,
			},
		},
	}
}

type ConfigClient struct {
	Cli rpc.GenericClient
}

func (c ConfigClient) GetCurrentStatus(ctx context.Context, sessionID int) (res GetCurrentStatusRes, err error) {
	__arg := GetCurrentStatusArg{SessionID: sessionID}
	err = c.Cli.Call(ctx, "keybase.1.config.getCurrentStatus", []interface{}{__arg}, &res)
	return
}

func (c ConfigClient) GetExtendedStatus(ctx context.Context, sessionID int) (res ExtendedStatus, err error) {
	__arg := GetExtendedStatusArg{SessionID: sessionID}
	err = c.Cli.Call(ctx, "keybase.1.config.getExtendedStatus", []interface{}{__arg}, &res)
	return
}

func (c ConfigClient) GetConfig(ctx context.Context, sessionID int) (res Config, err error) {
	__arg := GetConfigArg{SessionID: sessionID}
	err = c.Cli.Call(ctx, "keybase.1.config.getConfig", []interface{}{__arg}, &res)
	return
}

func (c ConfigClient) SetUserConfig(ctx context.Context, __arg SetUserConfigArg) (err error) {
	err = c.Cli.Call(ctx, "keybase.1.config.setUserConfig", []interface{}{__arg}, nil)
	return
}

func (c ConfigClient) SetPath(ctx context.Context, __arg SetPathArg) (err error) {
	err = c.Cli.Call(ctx, "keybase.1.config.setPath", []interface{}{__arg}, nil)
	return
}

func (c ConfigClient) HelloIAm(ctx context.Context, details ClientDetails) (err error) {
	__arg := HelloIAmArg{Details: details}
	err = c.Cli.Call(ctx, "keybase.1.config.helloIAm", []interface{}{__arg}, nil)
	return
}

func (c ConfigClient) SetValue(ctx context.Context, __arg SetValueArg) (err error) {
	err = c.Cli.Call(ctx, "keybase.1.config.setValue", []interface{}{__arg}, nil)
	return
}

func (c ConfigClient) ClearValue(ctx context.Context, path string) (err error) {
	__arg := ClearValueArg{Path: path}
	err = c.Cli.Call(ctx, "keybase.1.config.clearValue", []interface{}{__arg}, nil)
	return
}

func (c ConfigClient) GetValue(ctx context.Context, path string) (res ConfigValue, err error) {
	__arg := GetValueArg{Path: path}
	err = c.Cli.Call(ctx, "keybase.1.config.getValue", []interface{}{__arg}, &res)
	return
}
