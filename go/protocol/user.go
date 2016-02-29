package keybase1

import (
	rpc "github.com/keybase/go-framed-msgpack-rpc"
	context "golang.org/x/net/context"
)

type Tracker struct {
	Tracker UID  `codec:"tracker" json:"tracker"`
	Status  int  `codec:"status" json:"status"`
	MTime   Time `codec:"mTime" json:"mTime"`
}

type TrackProof struct {
	ProofType string `codec:"proofType" json:"proofType"`
	ProofName string `codec:"proofName" json:"proofName"`
	IdString  string `codec:"idString" json:"idString"`
}

type WebProof struct {
	Hostname  string   `codec:"hostname" json:"hostname"`
	Protocols []string `codec:"protocols" json:"protocols"`
}

type Proofs struct {
	Social     []TrackProof `codec:"social" json:"social"`
	Web        []WebProof   `codec:"web" json:"web"`
	PublicKeys []PublicKey  `codec:"publicKeys" json:"publicKeys"`
}

type UserSummary struct {
	Uid          UID    `codec:"uid" json:"uid"`
	Username     string `codec:"username" json:"username"`
	Thumbnail    string `codec:"thumbnail" json:"thumbnail"`
	IdVersion    int    `codec:"idVersion" json:"idVersion"`
	FullName     string `codec:"fullName" json:"fullName"`
	Bio          string `codec:"bio" json:"bio"`
	Proofs       Proofs `codec:"proofs" json:"proofs"`
	SigIDDisplay string `codec:"sigIDDisplay" json:"sigIDDisplay"`
	TrackTime    Time   `codec:"trackTime" json:"trackTime"`
}

type SearchComponent struct {
	Key   string  `codec:"key" json:"key"`
	Value string  `codec:"value" json:"value"`
	Score float64 `codec:"score" json:"score"`
}

type SearchResult struct {
	Uid        UID               `codec:"uid" json:"uid"`
	Username   string            `codec:"username" json:"username"`
	Components []SearchComponent `codec:"components" json:"components"`
	Score      float64           `codec:"score" json:"score"`
}

type ListTrackersArg struct {
	SessionID int `codec:"sessionID" json:"sessionID"`
	Uid       UID `codec:"uid" json:"uid"`
}

type ListTrackersByNameArg struct {
	SessionID int    `codec:"sessionID" json:"sessionID"`
	Username  string `codec:"username" json:"username"`
}

type ListTrackersSelfArg struct {
	SessionID int `codec:"sessionID" json:"sessionID"`
}

type LoadUncheckedUserSummariesArg struct {
	SessionID int   `codec:"sessionID" json:"sessionID"`
	Uids      []UID `codec:"uids" json:"uids"`
}

type LoadUserArg struct {
	SessionID int `codec:"sessionID" json:"sessionID"`
	Uid       UID `codec:"uid" json:"uid"`
}

type LoadUserPlusKeysArg struct {
	SessionID int  `codec:"sessionID" json:"sessionID"`
	Uid       UID  `codec:"uid" json:"uid"`
	CacheOK   bool `codec:"cacheOK" json:"cacheOK"`
}

type LoadPublicKeysArg struct {
	SessionID int `codec:"sessionID" json:"sessionID"`
	Uid       UID `codec:"uid" json:"uid"`
}

type ListTrackingArg struct {
	SessionID int    `codec:"sessionID" json:"sessionID"`
	Filter    string `codec:"filter" json:"filter"`
}

type ListTrackingJSONArg struct {
	SessionID int    `codec:"sessionID" json:"sessionID"`
	Filter    string `codec:"filter" json:"filter"`
	Verbose   bool   `codec:"verbose" json:"verbose"`
}

type SearchArg struct {
	SessionID int    `codec:"sessionID" json:"sessionID"`
	Query     string `codec:"query" json:"query"`
}

type UserInterface interface {
	ListTrackers(context.Context, ListTrackersArg) ([]Tracker, error)
	ListTrackersByName(context.Context, ListTrackersByNameArg) ([]Tracker, error)
	ListTrackersSelf(context.Context, int) ([]Tracker, error)
	LoadUncheckedUserSummaries(context.Context, LoadUncheckedUserSummariesArg) ([]UserSummary, error)
	LoadUser(context.Context, LoadUserArg) (User, error)
	LoadUserPlusKeys(context.Context, LoadUserPlusKeysArg) (UserPlusKeys, error)
	LoadPublicKeys(context.Context, LoadPublicKeysArg) ([]PublicKey, error)
	ListTracking(context.Context, ListTrackingArg) ([]UserSummary, error)
	ListTrackingJSON(context.Context, ListTrackingJSONArg) (string, error)
	Search(context.Context, SearchArg) ([]SearchResult, error)
}

func UserProtocol(i UserInterface) rpc.Protocol {
	return rpc.Protocol{
		Name: "keybase.1.user",
		Methods: map[string]rpc.ServeHandlerDescription{
			"listTrackers": {
				MakeArg: func() interface{} {
					ret := make([]ListTrackersArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]ListTrackersArg)
					if !ok {
						err = rpc.NewTypeError((*[]ListTrackersArg)(nil), args)
						return
					}
					ret, err = i.ListTrackers(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"listTrackersByName": {
				MakeArg: func() interface{} {
					ret := make([]ListTrackersByNameArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]ListTrackersByNameArg)
					if !ok {
						err = rpc.NewTypeError((*[]ListTrackersByNameArg)(nil), args)
						return
					}
					ret, err = i.ListTrackersByName(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"listTrackersSelf": {
				MakeArg: func() interface{} {
					ret := make([]ListTrackersSelfArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]ListTrackersSelfArg)
					if !ok {
						err = rpc.NewTypeError((*[]ListTrackersSelfArg)(nil), args)
						return
					}
					ret, err = i.ListTrackersSelf(ctx, (*typedArgs)[0].SessionID)
					return
				},
				MethodType: rpc.MethodCall,
			},
			"loadUncheckedUserSummaries": {
				MakeArg: func() interface{} {
					ret := make([]LoadUncheckedUserSummariesArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]LoadUncheckedUserSummariesArg)
					if !ok {
						err = rpc.NewTypeError((*[]LoadUncheckedUserSummariesArg)(nil), args)
						return
					}
					ret, err = i.LoadUncheckedUserSummaries(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"loadUser": {
				MakeArg: func() interface{} {
					ret := make([]LoadUserArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]LoadUserArg)
					if !ok {
						err = rpc.NewTypeError((*[]LoadUserArg)(nil), args)
						return
					}
					ret, err = i.LoadUser(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"loadUserPlusKeys": {
				MakeArg: func() interface{} {
					ret := make([]LoadUserPlusKeysArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]LoadUserPlusKeysArg)
					if !ok {
						err = rpc.NewTypeError((*[]LoadUserPlusKeysArg)(nil), args)
						return
					}
					ret, err = i.LoadUserPlusKeys(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"loadPublicKeys": {
				MakeArg: func() interface{} {
					ret := make([]LoadPublicKeysArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]LoadPublicKeysArg)
					if !ok {
						err = rpc.NewTypeError((*[]LoadPublicKeysArg)(nil), args)
						return
					}
					ret, err = i.LoadPublicKeys(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"listTracking": {
				MakeArg: func() interface{} {
					ret := make([]ListTrackingArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]ListTrackingArg)
					if !ok {
						err = rpc.NewTypeError((*[]ListTrackingArg)(nil), args)
						return
					}
					ret, err = i.ListTracking(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"listTrackingJSON": {
				MakeArg: func() interface{} {
					ret := make([]ListTrackingJSONArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]ListTrackingJSONArg)
					if !ok {
						err = rpc.NewTypeError((*[]ListTrackingJSONArg)(nil), args)
						return
					}
					ret, err = i.ListTrackingJSON(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"search": {
				MakeArg: func() interface{} {
					ret := make([]SearchArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]SearchArg)
					if !ok {
						err = rpc.NewTypeError((*[]SearchArg)(nil), args)
						return
					}
					ret, err = i.Search(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
		},
	}
}

type UserClient struct {
	Cli rpc.GenericClient
}

func (c UserClient) ListTrackers(ctx context.Context, __arg ListTrackersArg) (res []Tracker, err error) {
	err = c.Cli.Call(ctx, "keybase.1.user.listTrackers", []interface{}{__arg}, &res)
	return
}

func (c UserClient) ListTrackersByName(ctx context.Context, __arg ListTrackersByNameArg) (res []Tracker, err error) {
	err = c.Cli.Call(ctx, "keybase.1.user.listTrackersByName", []interface{}{__arg}, &res)
	return
}

func (c UserClient) ListTrackersSelf(ctx context.Context, sessionID int) (res []Tracker, err error) {
	__arg := ListTrackersSelfArg{SessionID: sessionID}
	err = c.Cli.Call(ctx, "keybase.1.user.listTrackersSelf", []interface{}{__arg}, &res)
	return
}

func (c UserClient) LoadUncheckedUserSummaries(ctx context.Context, __arg LoadUncheckedUserSummariesArg) (res []UserSummary, err error) {
	err = c.Cli.Call(ctx, "keybase.1.user.loadUncheckedUserSummaries", []interface{}{__arg}, &res)
	return
}

func (c UserClient) LoadUser(ctx context.Context, __arg LoadUserArg) (res User, err error) {
	err = c.Cli.Call(ctx, "keybase.1.user.loadUser", []interface{}{__arg}, &res)
	return
}

func (c UserClient) LoadUserPlusKeys(ctx context.Context, __arg LoadUserPlusKeysArg) (res UserPlusKeys, err error) {
	err = c.Cli.Call(ctx, "keybase.1.user.loadUserPlusKeys", []interface{}{__arg}, &res)
	return
}

func (c UserClient) LoadPublicKeys(ctx context.Context, __arg LoadPublicKeysArg) (res []PublicKey, err error) {
	err = c.Cli.Call(ctx, "keybase.1.user.loadPublicKeys", []interface{}{__arg}, &res)
	return
}

func (c UserClient) ListTracking(ctx context.Context, __arg ListTrackingArg) (res []UserSummary, err error) {
	err = c.Cli.Call(ctx, "keybase.1.user.listTracking", []interface{}{__arg}, &res)
	return
}

func (c UserClient) ListTrackingJSON(ctx context.Context, __arg ListTrackingJSONArg) (res string, err error) {
	err = c.Cli.Call(ctx, "keybase.1.user.listTrackingJSON", []interface{}{__arg}, &res)
	return
}

func (c UserClient) Search(ctx context.Context, __arg SearchArg) (res []SearchResult, err error) {
	err = c.Cli.Call(ctx, "keybase.1.user.search", []interface{}{__arg}, &res)
	return
}
