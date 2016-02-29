package keybase1

import (
	rpc "github.com/keybase/go-framed-msgpack-rpc"
	context "golang.org/x/net/context"
)

type SignMode int

const (
	SignMode_ATTACHED SignMode = 0
	SignMode_DETACHED SignMode = 1
	SignMode_CLEAR    SignMode = 2
)

type PGPSignOptions struct {
	KeyQuery  string   `codec:"keyQuery" json:"keyQuery"`
	Mode      SignMode `codec:"mode" json:"mode"`
	BinaryIn  bool     `codec:"binaryIn" json:"binaryIn"`
	BinaryOut bool     `codec:"binaryOut" json:"binaryOut"`
}

type PGPEncryptOptions struct {
	Recipients []string `codec:"recipients" json:"recipients"`
	NoSign     bool     `codec:"noSign" json:"noSign"`
	NoSelf     bool     `codec:"noSelf" json:"noSelf"`
	BinaryOut  bool     `codec:"binaryOut" json:"binaryOut"`
	KeyQuery   string   `codec:"keyQuery" json:"keyQuery"`
}

type PGPSigVerification struct {
	IsSigned bool      `codec:"isSigned" json:"isSigned"`
	Verified bool      `codec:"verified" json:"verified"`
	Signer   User      `codec:"signer" json:"signer"`
	SignKey  PublicKey `codec:"signKey" json:"signKey"`
}

type PGPDecryptOptions struct {
	AssertSigned bool   `codec:"assertSigned" json:"assertSigned"`
	SignedBy     string `codec:"signedBy" json:"signedBy"`
}

type PGPVerifyOptions struct {
	SignedBy  string `codec:"signedBy" json:"signedBy"`
	Signature []byte `codec:"signature" json:"signature"`
}

type KeyInfo struct {
	Fingerprint string `codec:"fingerprint" json:"fingerprint"`
	Key         string `codec:"key" json:"key"`
	Desc        string `codec:"desc" json:"desc"`
}

type PGPQuery struct {
	Secret     bool   `codec:"secret" json:"secret"`
	Query      string `codec:"query" json:"query"`
	ExactMatch bool   `codec:"exactMatch" json:"exactMatch"`
}

type PGPCreateUids struct {
	UseDefault bool          `codec:"useDefault" json:"useDefault"`
	Ids        []PGPIdentity `codec:"ids" json:"ids"`
}

type PGPSignArg struct {
	SessionID int            `codec:"sessionID" json:"sessionID"`
	Source    Stream         `codec:"source" json:"source"`
	Sink      Stream         `codec:"sink" json:"sink"`
	Opts      PGPSignOptions `codec:"opts" json:"opts"`
}

type PGPPullArg struct {
	SessionID   int      `codec:"sessionID" json:"sessionID"`
	UserAsserts []string `codec:"userAsserts" json:"userAsserts"`
}

type PGPEncryptArg struct {
	SessionID int               `codec:"sessionID" json:"sessionID"`
	Source    Stream            `codec:"source" json:"source"`
	Sink      Stream            `codec:"sink" json:"sink"`
	Opts      PGPEncryptOptions `codec:"opts" json:"opts"`
}

type PGPDecryptArg struct {
	SessionID int               `codec:"sessionID" json:"sessionID"`
	Source    Stream            `codec:"source" json:"source"`
	Sink      Stream            `codec:"sink" json:"sink"`
	Opts      PGPDecryptOptions `codec:"opts" json:"opts"`
}

type PGPVerifyArg struct {
	SessionID int              `codec:"sessionID" json:"sessionID"`
	Source    Stream           `codec:"source" json:"source"`
	Opts      PGPVerifyOptions `codec:"opts" json:"opts"`
}

type PGPImportArg struct {
	SessionID  int    `codec:"sessionID" json:"sessionID"`
	Key        []byte `codec:"key" json:"key"`
	PushSecret bool   `codec:"pushSecret" json:"pushSecret"`
}

type PGPExportArg struct {
	SessionID int      `codec:"sessionID" json:"sessionID"`
	Options   PGPQuery `codec:"options" json:"options"`
}

type PGPExportByFingerprintArg struct {
	SessionID int      `codec:"sessionID" json:"sessionID"`
	Options   PGPQuery `codec:"options" json:"options"`
}

type PGPExportByKIDArg struct {
	SessionID int      `codec:"sessionID" json:"sessionID"`
	Options   PGPQuery `codec:"options" json:"options"`
}

type PGPKeyGenArg struct {
	SessionID   int           `codec:"sessionID" json:"sessionID"`
	PrimaryBits int           `codec:"primaryBits" json:"primaryBits"`
	SubkeyBits  int           `codec:"subkeyBits" json:"subkeyBits"`
	CreateUids  PGPCreateUids `codec:"createUids" json:"createUids"`
	AllowMulti  bool          `codec:"allowMulti" json:"allowMulti"`
	DoExport    bool          `codec:"doExport" json:"doExport"`
	PushSecret  bool          `codec:"pushSecret" json:"pushSecret"`
}

type PGPDeletePrimaryArg struct {
	SessionID int `codec:"sessionID" json:"sessionID"`
}

type PGPSelectArg struct {
	SessionID        int    `codec:"sessionID" json:"sessionID"`
	FingerprintQuery string `codec:"fingerprintQuery" json:"fingerprintQuery"`
	AllowMulti       bool   `codec:"allowMulti" json:"allowMulti"`
	SkipImport       bool   `codec:"skipImport" json:"skipImport"`
	OnlyImport       bool   `codec:"onlyImport" json:"onlyImport"`
}

type PGPUpdateArg struct {
	SessionID    int      `codec:"sessionID" json:"sessionID"`
	All          bool     `codec:"all" json:"all"`
	Fingerprints []string `codec:"fingerprints" json:"fingerprints"`
}

type PGPInterface interface {
	PGPSign(context.Context, PGPSignArg) error
	PGPPull(context.Context, PGPPullArg) error
	PGPEncrypt(context.Context, PGPEncryptArg) error
	PGPDecrypt(context.Context, PGPDecryptArg) (PGPSigVerification, error)
	PGPVerify(context.Context, PGPVerifyArg) (PGPSigVerification, error)
	PGPImport(context.Context, PGPImportArg) error
	PGPExport(context.Context, PGPExportArg) ([]KeyInfo, error)
	PGPExportByFingerprint(context.Context, PGPExportByFingerprintArg) ([]KeyInfo, error)
	PGPExportByKID(context.Context, PGPExportByKIDArg) ([]KeyInfo, error)
	PGPKeyGen(context.Context, PGPKeyGenArg) error
	PGPDeletePrimary(context.Context, int) error
	PGPSelect(context.Context, PGPSelectArg) error
	PGPUpdate(context.Context, PGPUpdateArg) error
}

func PGPProtocol(i PGPInterface) rpc.Protocol {
	return rpc.Protocol{
		Name: "keybase.1.pgp",
		Methods: map[string]rpc.ServeHandlerDescription{
			"pgpSign": {
				MakeArg: func() interface{} {
					ret := make([]PGPSignArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]PGPSignArg)
					if !ok {
						err = rpc.NewTypeError((*[]PGPSignArg)(nil), args)
						return
					}
					err = i.PGPSign(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"pgpPull": {
				MakeArg: func() interface{} {
					ret := make([]PGPPullArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]PGPPullArg)
					if !ok {
						err = rpc.NewTypeError((*[]PGPPullArg)(nil), args)
						return
					}
					err = i.PGPPull(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"pgpEncrypt": {
				MakeArg: func() interface{} {
					ret := make([]PGPEncryptArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]PGPEncryptArg)
					if !ok {
						err = rpc.NewTypeError((*[]PGPEncryptArg)(nil), args)
						return
					}
					err = i.PGPEncrypt(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"pgpDecrypt": {
				MakeArg: func() interface{} {
					ret := make([]PGPDecryptArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]PGPDecryptArg)
					if !ok {
						err = rpc.NewTypeError((*[]PGPDecryptArg)(nil), args)
						return
					}
					ret, err = i.PGPDecrypt(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"pgpVerify": {
				MakeArg: func() interface{} {
					ret := make([]PGPVerifyArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]PGPVerifyArg)
					if !ok {
						err = rpc.NewTypeError((*[]PGPVerifyArg)(nil), args)
						return
					}
					ret, err = i.PGPVerify(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"pgpImport": {
				MakeArg: func() interface{} {
					ret := make([]PGPImportArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]PGPImportArg)
					if !ok {
						err = rpc.NewTypeError((*[]PGPImportArg)(nil), args)
						return
					}
					err = i.PGPImport(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"pgpExport": {
				MakeArg: func() interface{} {
					ret := make([]PGPExportArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]PGPExportArg)
					if !ok {
						err = rpc.NewTypeError((*[]PGPExportArg)(nil), args)
						return
					}
					ret, err = i.PGPExport(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"pgpExportByFingerprint": {
				MakeArg: func() interface{} {
					ret := make([]PGPExportByFingerprintArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]PGPExportByFingerprintArg)
					if !ok {
						err = rpc.NewTypeError((*[]PGPExportByFingerprintArg)(nil), args)
						return
					}
					ret, err = i.PGPExportByFingerprint(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"pgpExportByKID": {
				MakeArg: func() interface{} {
					ret := make([]PGPExportByKIDArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]PGPExportByKIDArg)
					if !ok {
						err = rpc.NewTypeError((*[]PGPExportByKIDArg)(nil), args)
						return
					}
					ret, err = i.PGPExportByKID(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"pgpKeyGen": {
				MakeArg: func() interface{} {
					ret := make([]PGPKeyGenArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]PGPKeyGenArg)
					if !ok {
						err = rpc.NewTypeError((*[]PGPKeyGenArg)(nil), args)
						return
					}
					err = i.PGPKeyGen(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"pgpDeletePrimary": {
				MakeArg: func() interface{} {
					ret := make([]PGPDeletePrimaryArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]PGPDeletePrimaryArg)
					if !ok {
						err = rpc.NewTypeError((*[]PGPDeletePrimaryArg)(nil), args)
						return
					}
					err = i.PGPDeletePrimary(ctx, (*typedArgs)[0].SessionID)
					return
				},
				MethodType: rpc.MethodCall,
			},
			"pgpSelect": {
				MakeArg: func() interface{} {
					ret := make([]PGPSelectArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]PGPSelectArg)
					if !ok {
						err = rpc.NewTypeError((*[]PGPSelectArg)(nil), args)
						return
					}
					err = i.PGPSelect(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
			"pgpUpdate": {
				MakeArg: func() interface{} {
					ret := make([]PGPUpdateArg, 1)
					return &ret
				},
				Handler: func(ctx context.Context, args interface{}) (ret interface{}, err error) {
					typedArgs, ok := args.(*[]PGPUpdateArg)
					if !ok {
						err = rpc.NewTypeError((*[]PGPUpdateArg)(nil), args)
						return
					}
					err = i.PGPUpdate(ctx, (*typedArgs)[0])
					return
				},
				MethodType: rpc.MethodCall,
			},
		},
	}
}

type PGPClient struct {
	Cli rpc.GenericClient
}

func (c PGPClient) PGPSign(ctx context.Context, __arg PGPSignArg) (err error) {
	err = c.Cli.Call(ctx, "keybase.1.pgp.pgpSign", []interface{}{__arg}, nil)
	return
}

func (c PGPClient) PGPPull(ctx context.Context, __arg PGPPullArg) (err error) {
	err = c.Cli.Call(ctx, "keybase.1.pgp.pgpPull", []interface{}{__arg}, nil)
	return
}

func (c PGPClient) PGPEncrypt(ctx context.Context, __arg PGPEncryptArg) (err error) {
	err = c.Cli.Call(ctx, "keybase.1.pgp.pgpEncrypt", []interface{}{__arg}, nil)
	return
}

func (c PGPClient) PGPDecrypt(ctx context.Context, __arg PGPDecryptArg) (res PGPSigVerification, err error) {
	err = c.Cli.Call(ctx, "keybase.1.pgp.pgpDecrypt", []interface{}{__arg}, &res)
	return
}

func (c PGPClient) PGPVerify(ctx context.Context, __arg PGPVerifyArg) (res PGPSigVerification, err error) {
	err = c.Cli.Call(ctx, "keybase.1.pgp.pgpVerify", []interface{}{__arg}, &res)
	return
}

func (c PGPClient) PGPImport(ctx context.Context, __arg PGPImportArg) (err error) {
	err = c.Cli.Call(ctx, "keybase.1.pgp.pgpImport", []interface{}{__arg}, nil)
	return
}

func (c PGPClient) PGPExport(ctx context.Context, __arg PGPExportArg) (res []KeyInfo, err error) {
	err = c.Cli.Call(ctx, "keybase.1.pgp.pgpExport", []interface{}{__arg}, &res)
	return
}

func (c PGPClient) PGPExportByFingerprint(ctx context.Context, __arg PGPExportByFingerprintArg) (res []KeyInfo, err error) {
	err = c.Cli.Call(ctx, "keybase.1.pgp.pgpExportByFingerprint", []interface{}{__arg}, &res)
	return
}

func (c PGPClient) PGPExportByKID(ctx context.Context, __arg PGPExportByKIDArg) (res []KeyInfo, err error) {
	err = c.Cli.Call(ctx, "keybase.1.pgp.pgpExportByKID", []interface{}{__arg}, &res)
	return
}

func (c PGPClient) PGPKeyGen(ctx context.Context, __arg PGPKeyGenArg) (err error) {
	err = c.Cli.Call(ctx, "keybase.1.pgp.pgpKeyGen", []interface{}{__arg}, nil)
	return
}

func (c PGPClient) PGPDeletePrimary(ctx context.Context, sessionID int) (err error) {
	__arg := PGPDeletePrimaryArg{SessionID: sessionID}
	err = c.Cli.Call(ctx, "keybase.1.pgp.pgpDeletePrimary", []interface{}{__arg}, nil)
	return
}

func (c PGPClient) PGPSelect(ctx context.Context, __arg PGPSelectArg) (err error) {
	err = c.Cli.Call(ctx, "keybase.1.pgp.pgpSelect", []interface{}{__arg}, nil)
	return
}

func (c PGPClient) PGPUpdate(ctx context.Context, __arg PGPUpdateArg) (err error) {
	err = c.Cli.Call(ctx, "keybase.1.pgp.pgpUpdate", []interface{}{__arg}, nil)
	return
}
