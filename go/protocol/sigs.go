package keybase1

import (
	rpc "github.com/keybase/go-framed-msgpack-rpc"
	context "golang.org/x/net/context"
)

type Sig struct {
	Seqno        int    `codec:"seqno" json:"seqno"`
	SigID        SigID  `codec:"sigID" json:"sigID"`
	SigIDDisplay string `codec:"sigIDDisplay" json:"sigIDDisplay"`
	Type         string `codec:"type" json:"type"`
	CTime        Time   `codec:"cTime" json:"cTime"`
	Revoked      bool   `codec:"revoked" json:"revoked"`
	Active       bool   `codec:"active" json:"active"`
	Key          string `codec:"key" json:"key"`
	Body         string `codec:"body" json:"body"`
}

type SigTypes struct {
	Track          bool `codec:"track" json:"track"`
	Proof          bool `codec:"proof" json:"proof"`
	Cryptocurrency bool `codec:"cryptocurrency" json:"cryptocurrency"`
	IsSelf         bool `codec:"isSelf" json:"isSelf"`
}

type SigListArgs struct {
	SessionID int       `codec:"sessionID" json:"sessionID"`
	Username  string    `codec:"username" json:"username"`
	AllKeys   bool      `codec:"allKeys" json:"allKeys"`
	Types     *SigTypes `codec:"types,omitempty" json:"types,omitempty"`
	Filterx   string    `codec:"filterx" json:"filterx"`
	Verbose   bool      `codec:"verbose" json:"verbose"`
	Revoked   bool      `codec:"revoked" json:"revoked"`
}

type SigListArg struct {
	SessionID int         `codec:"sessionID" json:"sessionID"`
	Arg       SigListArgs `codec:"arg" json:"arg"`
}

type SigListJSONArg struct {
	SessionID int         `codec:"sessionID" json:"sessionID"`
	Arg       SigListArgs `codec:"arg" json:"arg"`
}

type SigsInterface interface {
	SigList(context.Context, SigListArg) ([]Sig, error)
	SigListJSON(context.Context, SigListJSONArg) (string, error)
}

func SigsProtocol(i SigsInterface) rpc.Protocol {
	return rpc.Protocol{
		Name: "keybase.1.sigs",
		Methods: map[string]rpc.ServeHandlerDescription{
			"sigList": {
				MakeArg: func() interface{} {
					ret := make([]SigListArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]SigListArg)
					if !ok {
						err = rpc.NewTypeError((*[]SigListArg)(nil), args)
						return
					}
					ret, err = i.SigList(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"sigListJSON": {
				MakeArg: func() interface{} {
					ret := make([]SigListJSONArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]SigListJSONArg)
					if !ok {
						err = rpc.NewTypeError((*[]SigListJSONArg)(nil), args)
						return
					}
					ret, err = i.SigListJSON(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
		},
	}
}

type SigsClient struct {
	Cli rpc.GenericClient
}

func (c SigsClient) SigList(ctx context.Context, __arg SigListArg) (res []Sig, err error) {
	err = c.Cli.Call(ctx, "keybase.1.sigs.sigList", []interface{}{__arg}, &res)
	return
}

func (c SigsClient) SigListJSON(ctx context.Context, __arg SigListJSONArg) (res string, err error) {
	err = c.Cli.Call(ctx, "keybase.1.sigs.sigListJSON", []interface{}{__arg}, &res)
	return
}
