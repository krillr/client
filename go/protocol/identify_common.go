package keybase1

import (
	rpc "github.com/keybase/go-framed-msgpack-rpc"
)

type TrackToken string
type TrackDiffType int

const (
	TrackDiffType_NONE               TrackDiffType = 0
	TrackDiffType_ERROR              TrackDiffType = 1
	TrackDiffType_CLASH              TrackDiffType = 2
	TrackDiffType_REVOKED            TrackDiffType = 3
	TrackDiffType_UPGRADED           TrackDiffType = 4
	TrackDiffType_NEW                TrackDiffType = 5
	TrackDiffType_REMOTE_FAIL        TrackDiffType = 6
	TrackDiffType_REMOTE_WORKING     TrackDiffType = 7
	TrackDiffType_REMOTE_CHANGED     TrackDiffType = 8
	TrackDiffType_NEW_ELDEST         TrackDiffType = 9
	TrackDiffType_NONE_VIA_TEMPORARY TrackDiffType = 10
)

type TrackDiff struct {
	Type          TrackDiffType `codec:"type" json:"type"`
	DisplayMarkup string        `codec:"displayMarkup" json:"displayMarkup"`
}

type TrackSummary struct {
	Username string `codec:"username" json:"username"`
	Time     Time   `codec:"time" json:"time"`
	IsRemote bool   `codec:"isRemote" json:"isRemote"`
}

type TrackStatus int

const (
	TrackStatus_NEW_OK            TrackStatus = 1
	TrackStatus_NEW_ZERO_PROOFS   TrackStatus = 2
	TrackStatus_NEW_FAIL_PROOFS   TrackStatus = 3
	TrackStatus_UPDATE_BROKEN     TrackStatus = 4
	TrackStatus_UPDATE_NEW_PROOFS TrackStatus = 5
	TrackStatus_UPDATE_OK         TrackStatus = 6
)

type TrackOptions struct {
	LocalOnly     bool `codec:"localOnly" json:"localOnly"`
	BypassConfirm bool `codec:"bypassConfirm" json:"bypassConfirm"`
	ForceRetrack  bool `codec:"forceRetrack" json:"forceRetrack"`
	ExpiringLocal bool `codec:"expiringLocal" json:"expiringLocal"`
}

type IdentifyReasonType int

const (
	IdentifyReasonType_NONE     IdentifyReasonType = 0
	IdentifyReasonType_ID       IdentifyReasonType = 1
	IdentifyReasonType_TRACK    IdentifyReasonType = 2
	IdentifyReasonType_ENCRYPT  IdentifyReasonType = 3
	IdentifyReasonType_DECRYPT  IdentifyReasonType = 4
	IdentifyReasonType_VERIFY   IdentifyReasonType = 5
	IdentifyReasonType_RESOURCE IdentifyReasonType = 6
)

type IdentifyReason struct {
	Type     IdentifyReasonType `codec:"type" json:"type"`
	Reason   string             `codec:"reason" json:"reason"`
	Resource string             `codec:"resource" json:"resource"`
}

type IdentifyOutcome struct {
	Username          string         `codec:"username" json:"username"`
	Status            *Status        `codec:"status,omitempty" json:"status,omitempty"`
	Warnings          []string       `codec:"warnings" json:"warnings"`
	TrackUsed         *TrackSummary  `codec:"trackUsed,omitempty" json:"trackUsed,omitempty"`
	TrackStatus       TrackStatus    `codec:"trackStatus" json:"trackStatus"`
	NumTrackFailures  int            `codec:"numTrackFailures" json:"numTrackFailures"`
	NumTrackChanges   int            `codec:"numTrackChanges" json:"numTrackChanges"`
	NumProofFailures  int            `codec:"numProofFailures" json:"numProofFailures"`
	NumRevoked        int            `codec:"numRevoked" json:"numRevoked"`
	NumProofSuccesses int            `codec:"numProofSuccesses" json:"numProofSuccesses"`
	Revoked           []TrackDiff    `codec:"revoked" json:"revoked"`
	TrackOptions      TrackOptions   `codec:"trackOptions" json:"trackOptions"`
	ForPGPPull        bool           `codec:"forPGPPull" json:"forPGPPull"`
	Reason            IdentifyReason `codec:"reason" json:"reason"`
}

type IdentifyRes struct {
	User       *User           `codec:"user,omitempty" json:"user,omitempty"`
	PublicKeys []PublicKey     `codec:"publicKeys" json:"publicKeys"`
	Outcome    IdentifyOutcome `codec:"outcome" json:"outcome"`
	TrackToken TrackToken      `codec:"trackToken" json:"trackToken"`
}

type RemoteProof struct {
	ProofType     ProofType `codec:"proofType" json:"proofType"`
	Key           string    `codec:"key" json:"key"`
	Value         string    `codec:"value" json:"value"`
	DisplayMarkup string    `codec:"displayMarkup" json:"displayMarkup"`
	SigID         SigID     `codec:"sigID" json:"sigID"`
	MTime         Time      `codec:"mTime" json:"mTime"`
}

type IdentifyCommonInterface interface {
}

func IdentifyCommonProtocol(i IdentifyCommonInterface) rpc.Protocol {
	return rpc.Protocol{
		Name:    "keybase.1.identifyCommon",
		Methods: map[string]rpc.ServeHandlerDescription{},
	}
}

type IdentifyCommonClient struct {
	Cli rpc.GenericClient
}
