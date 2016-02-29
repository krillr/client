package keybase1

import (
	rpc "github.com/keybase/go-framed-msgpack-rpc"
	context "golang.org/x/net/context"
)

type MetadataUpdateArg struct {
	FolderID string `codec:"folderID" json:"folderID"`
	Revision int64  `codec:"revision" json:"revision"`
}

type FolderNeedsRekeyArg struct {
	FolderID string `codec:"folderID" json:"folderID"`
	Revision int64  `codec:"revision" json:"revision"`
}

type MetadataUpdateInterface interface {
	MetadataUpdate(context.Context, MetadataUpdateArg) error
	FolderNeedsRekey(context.Context, FolderNeedsRekeyArg) error
}

func MetadataUpdateProtocol(i MetadataUpdateInterface) rpc.Protocol {
	return rpc.Protocol{
		Name: "keybase.1.metadataUpdate",
		Methods: map[string]rpc.ServeHandlerDescription{
			"metadataUpdate": {
				MakeArg: func() interface{} {
					ret := make([]MetadataUpdateArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]MetadataUpdateArg)
					if !ok {
						err = rpc.NewTypeError((*[]MetadataUpdateArg)(nil), args)
						return
					}
					err = i.MetadataUpdate(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"folderNeedsRekey": {
				MakeArg: func() interface{} {
					ret := make([]FolderNeedsRekeyArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]FolderNeedsRekeyArg)
					if !ok {
						err = rpc.NewTypeError((*[]FolderNeedsRekeyArg)(nil), args)
						return
					}
					err = i.FolderNeedsRekey(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
		},
	}
}

type MetadataUpdateClient struct {
	Cli rpc.GenericClient
}

func (c MetadataUpdateClient) MetadataUpdate(ctx context.Context, __arg MetadataUpdateArg) (err error) {
	err = c.Cli.Call(ctx, "keybase.1.metadataUpdate.metadataUpdate", []interface{}{__arg}, nil)
	return
}

func (c MetadataUpdateClient) FolderNeedsRekey(ctx context.Context, __arg FolderNeedsRekeyArg) (err error) {
	err = c.Cli.Call(ctx, "keybase.1.metadataUpdate.folderNeedsRekey", []interface{}{__arg}, nil)
	return
}
