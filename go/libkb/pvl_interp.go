package libkb

import (
	b64 "encoding/base64"
	"fmt"
	"github.com/PuerkitoBio/goquery"
	keybase1 "github.com/keybase/client/go/protocol"
	jsonw "github.com/keybase/go-jsonw"
	"io/ioutil"
	"log"
	"net"
	"os/user"
	"regexp"
	"strings"
	"sync"
)

var hardcodedPVL jsonw.Wrapper

// Whether to use PVL for verifying proofs.
const UsePvl = true

// Supported version of pvl.
const PvlSupportedVersion int = 1

type PvlScriptState struct {
	PC           int32
	Service      keybase1.ProofType
	Vars         PvlScriptVariables
	ActiveString string
	FetchURL     string
	HasFetched   bool
	FetchResult  *PvlFetchResult
	Test         bool // TODO temp
}

type PvlScriptVariables struct {
	UsernameService  string
	UsernameKeybase  string
	Sig              []byte
	SigIDMedium      string
	SigIDShort       string
	DNSProofHostname string
}

type PvlFetchResult struct {
	Mode PvlMode
	// One of these 3 must be filled.
	String string
	HTML   *goquery.Document
	JSON   *jsonw.Wrapper
}

type PvlMode int

const (
	PvlModeHTTPSJSON   PvlMode = 0
	PvlModeHTTPSHTML   PvlMode = 1
	PvlModeHTTPSSTRING PvlMode = 2
	PvlModeDNS         PvlMode = 3
)

// Check that a chunk of PVL is valid code.
// Will always accept valid code, may not always notice invalidities.
func PvlValidateChunk(pvl *jsonw.Wrapper, service keybase1.ProofType) ProofError {
	chunk := pvl

	// TODO service required.
	// TODO each service must be recognized.
	// TODO Each service must be a script or list of scripts.

	// Check the version.
	version, err := chunk.AtKey("pvl_version").GetInt()
	if err != nil {
		return NewProofError(keybase1.ProofStatus_INVALID_PVL,
			"PVL missing version number: %v", err)
	}
	if version != PvlSupportedVersion {
		return NewProofError(keybase1.ProofStatus_INVALID_PVL,
			"PVL is for the wrong version %v != %v", version, PvlSupportedVersion)
	}

	// Get the script.
	// TODO handle when it's a list of scripts. (this is dup'd below)
	serviceString, perr := serviceToString(service)
	if perr != nil {
		return perr
	}
	script, err := chunk.AtKey("services").AtKey(serviceString).ToArray()
	if err != nil {
		return NewProofError(keybase1.ProofStatus_INVALID_PVL,
			"PVL script is not an array: %v", err)
	}

	// Scan the script.
	var modeknown = false
	var mode PvlMode
	if service == keybase1.ProofType_DNS {
		modeknown = true
		mode = PvlModeDNS
	}
	scriptlen, err := script.Len()
	if err != nil {
		return NewProofError(keybase1.ProofStatus_INVALID_PVL,
			"Could not get length of script: %v", err)
	}
	for i := 0; i < scriptlen; i++ {
		ins := script.AtIndex(i)
		switch {
		case jsonHasKey(ins, "fetch"):
			fetchType, err := ins.AtKey("fetch").GetString()
			if err != nil {
				return NewProofError(keybase1.ProofStatus_INVALID_PVL,
					"Could not get fetch type %v", i)
			}

			if service == keybase1.ProofType_DNS {
				return NewProofError(keybase1.ProofStatus_INVALID_PVL,
					"DNS script cannot contain fetch instruction")
			}
			if modeknown {
				return NewProofError(keybase1.ProofStatus_INVALID_PVL,
					"Script cannot contain multiple fetch instructions")
			}
			switch fetchType {
			case "https_string":
				modeknown = true
				mode = PvlModeHTTPSSTRING
			case "https_html":
				modeknown = true
				mode = PvlModeHTTPSHTML
			case "https_json":
				modeknown = true
				mode = PvlModeHTTPSJSON
			}
		case jsonHasKey(ins, "selector_css"):
			switch {
			case service == keybase1.ProofType_DNS:
				return NewProofError(keybase1.ProofStatus_INVALID_PVL,
					"DNS script cannot css selector")
			case !modeknown:
				return NewProofError(keybase1.ProofStatus_INVALID_PVL,
					"Script cannot select before fetch")
			case mode != PvlModeHTTPSHTML:
				return NewProofError(keybase1.ProofStatus_INVALID_PVL,
					"Script contains CSS selector in non-html mode")
			}
		case jsonHasKey(ins, "selector_json"):
			switch {
			case service == keybase1.ProofType_DNS:
				return NewProofError(keybase1.ProofStatus_INVALID_PVL,
					"DNS script cannot json selector")
			case !modeknown:
				return NewProofError(keybase1.ProofStatus_INVALID_PVL,
					"Script cannot select before fetch")
			case mode != PvlModeHTTPSJSON:
				return NewProofError(keybase1.ProofStatus_INVALID_PVL,
					"Script contains json selector in non-json mode")
			}
		}
	}

	return nil
}

func CheckProof(g *GlobalContext, pvl *jsonw.Wrapper, service keybase1.ProofType, link RemoteProofChainLink, h SigHint) ProofError {
	chunk := pvl

	if perr := PvlValidateChunk(pvl, service); perr != nil {
		return perr
	}

	sigBody, sigID, err := OpenSig(link.GetArmoredSig())
	if err != nil {
		return NewProofError(keybase1.ProofStatus_BAD_SIGNATURE,
			"Bad signature: %v", err)
	}

	// Get the script.
	// TODO handle when it's a list of scripts.
	serviceString, perr := serviceToString(service)
	if perr != nil {
		return perr
	}
	script, err := chunk.AtKey("services").AtKey(serviceString).ToArray()
	if err != nil {
		return NewProofError(keybase1.ProofStatus_INVALID_PVL,
			"PVL script is not an array: %v", err)
	}

	// TODO special vars for DNS
	vars := PvlScriptVariables{
		UsernameService:  link.GetRemoteUsername(), // Blank for DNS-proofs
		UsernameKeybase:  link.GetUsername(),
		Sig:              sigBody,
		SigIDMedium:      sigID.ToMediumID(),
		SigIDShort:       sigID.ToShortID(),
		DNSProofHostname: link.GetHostname(), // Blank for non-DNS proofs
	}
	state := PvlScriptState{
		PC:           0,
		Service:      service,
		Vars:         vars,
		ActiveString: h.apiURL,
		FetchURL:     h.apiURL,
		HasFetched:   false,
		FetchResult:  nil,
	}

	if service == keybase1.ProofType_DNS {
		scripts := []*jsonw.Wrapper{script}
		perr = runDNS(g, scripts, state)
		if perr != nil {
			return perr
		}
	} else {
		perr = runScript(g, script, state)
		if perr != nil {
			return perr
		}
	}

	return nil
}

// Run each script on each TXT record of each domain.
// Succeed if any succeed.
func runDNS(g *GlobalContext, scripts []*jsonw.Wrapper, startstate PvlScriptState) ProofError {
	userdomain := startstate.Vars.DNSProofHostname
	domains := []string{userdomain, "_keybase." + userdomain}
	var firsterr ProofError
	for _, d := range domains {
		g.Log.Debug("Trying DNS: %v", d)

		err := runDNSOne(g, scripts, startstate, d)
		if err == nil {
			return nil
		}
		if firsterr == nil {
			firsterr = err
		}
	}

	return firsterr
}

func runDNSOne(g *GlobalContext, scripts []*jsonw.Wrapper, startstate PvlScriptState, domain string) ProofError {
	txts, err := net.LookupTXT(domain)
	if err != nil {
		return NewProofError(keybase1.ProofStatus_DNS_ERROR,
			"DNS failure for %s: %s", domain, err)
	}

	for _, record := range txts {
		g.Log.Debug("For %s, got TXT record: %s", domain, record)

		// Try all scripts.
		for _, script := range scripts {
			state := startstate
			state.ActiveString = record
			err = runScript(g, script, state)
			if err == nil {
				return nil
			}
		}
	}

	return NewProofError(keybase1.ProofStatus_NOT_FOUND,
		"Checked %d TXT entries of %s, but didn't find signature",
		len(txts), domain)
}

func runScript(g *GlobalContext, script *jsonw.Wrapper, startstate PvlScriptState) ProofError {
	var state = startstate
	// Run the script.
	// TODO special run for DNS.
	scriptlen, err := script.Len()
	if err != nil {
		return NewProofError(keybase1.ProofStatus_INVALID_PVL,
			"Could not get length of script: %v", err)
	}
	for i := 0; i < scriptlen; i++ {
		ins := script.AtIndex(i)

		// Sanity check.
		if int(state.PC) != i {
			return NewProofError(keybase1.ProofStatus_INVALID_PVL,
				fmt.Sprintf("Execution failure, PC mismatch %v %v", state.PC, i))
		}

		newstate, perr := runInstruction(g, ins, state)
		state = newstate
		if perr != nil {
			if perr.GetProofStatus() == keybase1.ProofStatus_INVALID_PVL {
				perr = NewProofError(keybase1.ProofStatus_INVALID_PVL,
					fmt.Sprintf("Invalid PVL (%v): %v", state.PC, perr.GetDesc()))
			}
			return perr
		}
		state.PC++
	}

	// Script executed successfully and with no errors.
	return nil
}

func runInstruction(g *GlobalContext, ins *jsonw.Wrapper, state PvlScriptState) (PvlScriptState, ProofError) {
	// TODO in general, maybe log some debug stuff instead of cramming instruction into error?
	// TODO use "error" key of instructions.
	// TODO tor errors
	// TODO Replace CONTENT_FAILURE failure with well-thought-out errors.
	// TODO a bad regex will cause a gross logging double-interpolation

	switch {
	case jsonHasKey(ins, "assert_regex_match"):
		template, err := ins.AtKey("assert_regex_match").GetString()
		if err != nil {
			return state, NewProofError(keybase1.ProofStatus_INVALID_PVL,
				"Could not get pattern %v", ins)
		}
		re, perr := interpretPvlRegex(template, state.Vars)
		if perr != nil {
			return state, perr
		}
		if !re.MatchString(state.ActiveString) {
			g.Log.Debug("PVL regex did not match: %v %v", re, state.ActiveString)
			return state, NewProofError(keybase1.ProofStatus_CONTENT_FAILURE,
				"Regex did not match %v", re)
		}

		return state, nil
	case jsonHasKey(ins, "assert_find_base64"):
		target, err := ins.AtKey("assert_find_base64").GetString()
		if err != nil {
			return state, NewProofError(keybase1.ProofStatus_INVALID_PVL,
				"Could not assert target %v", ins)
		}
		if target == "sig" {
			if FindBase64Block(state.ActiveString, state.Vars.Sig, false) {
				return state, nil
			}
			return state, NewProofError(keybase1.ProofStatus_TEXT_NOT_FOUND,
				"Signature not found")
		}
		// TODO change spec or make this work.
		return state, NewProofError(keybase1.ProofStatus_INVALID_PVL,
			"Can only assert_find_base64 for sig %v", ins)
	case jsonHasKey(ins, "whitespace_normalize"):
		state.ActiveString = WhitespaceNormalize(state.ActiveString)
		return state, nil
	case jsonHasKey(ins, "regex_capture"):
		template, err := ins.AtKey("regex_capture").GetString()
		if err != nil {
			return state, NewProofError(keybase1.ProofStatus_INVALID_PVL,
				"Could not get pattern %v", ins)
		}
		re, perr := interpretPvlRegex(template, state.Vars)
		if perr != nil {
			return state, perr
		}
		match := re.FindStringSubmatch(state.ActiveString)
		if len(match) < 2 {
			g.Log.Debug("PVL regex capture did not match: %v %v", re, state.ActiveString)
			return state, NewProofError(keybase1.ProofStatus_CONTENT_FAILURE,
				"Regex capture did not match: %v", re)
		}
		state.ActiveString = match[1]
		return state, nil
	case jsonHasKey(ins, "fetch"):
		fetchType, err := ins.AtKey("fetch").GetString()
		if err != nil {
			return state, NewProofError(keybase1.ProofStatus_INVALID_PVL,
				"Could not get fetch type %v", state.PC)
		}
		if state.FetchResult != nil {
			return state, NewProofError(keybase1.ProofStatus_INVALID_PVL,
				"Script cannot contain more than one fetch %v", state.PC)
		}
		// TODO ensure the url is https.
		// TODO maybe have this driven by preselected mode.
		// TODO ensure this isn't DNS.
		switch fetchType {
		case "https_string":
			res, err := g.XAPI.GetText(NewAPIArg(g, state.FetchURL))
			if err != nil {
				return state, XapiError(err, state.FetchURL)
			}
			state.FetchResult = &PvlFetchResult{
				Mode:   PvlModeHTTPSSTRING,
				String: res.Body,
			}
			state.ActiveString = state.FetchResult.String
			return state, nil
		case "https_json":
			return state, NewProofError(keybase1.ProofStatus_INVALID_PVL, "Not implemented %v", ins) // TODO
		case "https_html":
			res, err := g.XAPI.GetHTML(NewAPIArg(g, state.FetchURL))
			if err != nil {
				return state, XapiError(err, state.FetchURL)
			}
			state.FetchResult = &PvlFetchResult{
				Mode: PvlModeHTTPSHTML,
				HTML: res.GoQuery,
			}
			state.ActiveString = ""
			return state, nil
		default:
			return state, NewProofError(keybase1.ProofStatus_INVALID_PVL,
				"Unsupported fetch type %v", fetchType)
		}
	case jsonHasKey(ins, "selector_json"):
		return state, NewProofError(keybase1.ProofStatus_INVALID_PVL, "Not implemented %v", ins) // TODO
	/*
		case jsonHasKey(ins, "selector_css"):
			if state.FetchResult == nil || state.FetchResult.Mode != PvlModeHTTPSHTML {
				return state, NewProofError(keybase1.ProofStatus_INVALID_PVL,
					"Cannot use css selector with non-html fetch result")
			}

			mselector, err := ins.AtKey("selector_css").ToArray()
			if err != nil {
				return state, NewProofError(keybase1.ProofStatus_INVALID_PVL, "Invalid PVL: %v", err)
			}

			res, err := runCSSSelector(g, state.FetchResult.HTML, mselector)
			if err != nil {
				return err
			}

			state.ActiveString = res
			return state, nil
	*/
	/*
		case jsonHasKey(ins, "selector_css"):
			// TODO goquery specifies that it requires UTF8 encoding. Deal with that.
			if state.FetchResult == nil || state.FetchResult.Mode != PvlModeHTTPSHTML {
				return state, NewProofError(keybase1.ProofStatus_INVALID_PVL,
					"Cannot use css selector with non-html fetch result")
			}

			selector, err := ins.AtKey("selector_css").GetString()
			if err != nil {
				return state, NewProofError(keybase1.ProofStatus_INVALID_PVL, "Invalid PVL: %v", err)
			}

			selection := state.FetchResult.HTML.Find(selector)

			if selection.Length() == 0 {
				return state, NewProofError(keybase1.ProofStatus_CONTENT_FAILURE,
					"Css selector did not find %v", selector)
			}

			res, err := getSelectionContents(selection)
			if err != nil {
				return state, NewProofError(keybase1.ProofStatus_CONTENT_FAILURE,
					"Css selector could not html: %v", err)
			}

			state.ActiveString = res
			return state, nil
	*/
	case jsonHasKey(ins, "selector_css"):
		// TODO goquery specifies that it requires UTF8 encoding. Deal with that.
		if state.FetchResult == nil || state.FetchResult.Mode != PvlModeHTTPSHTML {
			return state, NewProofError(keybase1.ProofStatus_INVALID_PVL,
				"Cannot use css selector with non-html fetch result")
		}

		selectors, err := ins.AtKey("selector_css").ToArray()
		if err != nil {
			return state, NewProofError(keybase1.ProofStatus_INVALID_PVL,
				"CSS selectors must be an array: %v", err)
		}

		attr, err := ins.AtKey("attr").GetString()
		useAttr := err == nil

		selection, perr := runCSSSelector(g, state.FetchResult.HTML.Selection, selectors)
		if perr != nil {
			return state, perr
		}

		if selection.Size() < 1 {
			return state, NewProofError(keybase1.ProofStatus_CONTENT_FAILURE,
				"No elements matched by selector")
		}

		res, err := getSelectionContents(selection, useAttr, attr)
		if err != nil {
			return state, NewProofError(keybase1.ProofStatus_CONTENT_FAILURE,
				"Could not get html for selection: %v", err)
		}

		state.ActiveString = res
		return state, nil
	case jsonHasKey(ins, "transform_url"):
		return state, NewProofError(keybase1.ProofStatus_INVALID_PVL, "Not implemented %v", ins) // TODO
	default:
		return state, NewProofError(keybase1.ProofStatus_INVALID_PVL,
			"Unsupported PVL instruction %d", state.PC)
	}

	// TODO write this
	// switch pvl.Mode() {
	// case PVL_MODE_HTTPSJSON:
	// case PVL_MODE_HTTPSHTML:
	// case PVL_MODE_HTTPSSTRING:
	// case PVL_MODE_DNS:
	// }
}

// Get the HTML contents of all elements in a selection, concatenated by a space.
func getSelectionContents(selection *goquery.Selection, useAttr bool, attr string) (string, error) {
	len := selection.Length()
	results := make([]string, len)
	errs := make([]error, len)
	var wg sync.WaitGroup
	wg.Add(len)
	selection.Each(func(i int, element *goquery.Selection) {
		if useAttr {
			res, ok := element.Attr(attr)
			results[i] = res
			if !ok {
				errs[i] = fmt.Errorf("Could not get attr %v of element", attr)
			}
		} else {
			results[i] = element.Text()
			errs[i] = nil
		}
		wg.Done()
	})
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return "", err
		}
	}
	return strings.Join(results, " "), nil
}

// Run a PVL CSS selector.
// selectors is a list like [ "div .foo", 0, ".bar"] ].
// Each string runs a selector, each integer runs a Eq.
func runCSSSelector(g *GlobalContext, html *goquery.Selection, selectors *jsonw.Wrapper) (*goquery.Selection, ProofError) {
	// TODO recover. the goquery lib panics. :(

	nselectors, err := selectors.Len()
	if err != nil {
		return nil, NewProofError(keybase1.ProofStatus_INVALID_PVL,
			"Could not get length of selector list")
	}
	if nselectors < 1 {
		return nil, NewProofError(keybase1.ProofStatus_INVALID_PVL,
			"CSS selectors array must not be empty")
	}

	var selection *goquery.Selection
	selection = html

	for i := 0; i < nselectors; i++ {
		selector := selectors.AtIndex(i)

		selectorString, err := selector.GetString()
		selectorIsString := err == nil
		selectorIndex, err := selector.GetInt()
		selectorIsIndex := err == nil

		switch {
		case selectorIsIndex:
			selection = selection.Eq(selectorIndex)
		case selectorIsString:
			selection = selection.Find(selectorString)
		default:
			return nil, NewProofError(keybase1.ProofStatus_INVALID_PVL,
				"Selector entry string or int %v", selector)
		}
	}

	return selection, nil
}

/*
// Run a PVL CSS selector.
// mselector is a list like [ ["div" 0], [".foo" 1] ].
func runCSSSelector(g *GlobalContext, html *goquery.Document, mselector *jsonw.Wrapper) (string, ProofError) {
	pair, err := mselector.AtIndex(?).ToArray()
	if err != nil {
		return state, NewProofError(keybase1.ProofStatus_INVALID_PVL,
			"Selector entry must be an array %v", err)
	}

	perr := NewProofError(keybase1.ProofStatus_CONTENT_FAILURE,
		"Css selector did not find %v", pair)

	if pair.Len() != 2 {
		return state, NewProofError(keybase1.ProofStatus_INVALID_PVL,
			"Selector entry must be a pair")
	}

	// Get the selector string
	selector, err := pair.AtIndex(0).GetString()
	if err != nil {
		return state, NewProofError(keybase1.ProofStatus_INVALID_PVL,
			"Selector entry must cointain string: %v", err)
	}

	// Check whether the index specifier is {all: true}
	_, err := pair.AtIndex(1).AtKey("all").GetString()
	indexIsAll = err != nil
	var indexNumber
	if !indexIsAll {
		indexNumber, err := pair.AtIndex(1).GetInt()
		if err != nil {
			return state, NewProofError(keybase1.ProofStatus_INVALID_PVL,
				"Selector index must be all or an int: %v", err)
		}
	}

	selection := html.Find(selector)
	if selection.Length() == 0 {
		return perr
	}

	switch {
	case indexIsAll:
		rest = ? mselector

		for i = 0; i < selection.Length(); i++ {
			selection.Index(i)
		}

		res := runCSSSelector(g, element, rest)
		concat those things
		TODO acutally its more complicated.
	case indexNumber >= 0:
		straight index
	default:
		negative index
	}

}
*/

func interpretPvlRegex(template string, vars PvlScriptVariables) (*regexp.Regexp, ProofError) {
	perr := NewProofError(keybase1.ProofStatus_INVALID_PVL,
		"Could not build regex %v", template)

	// Parse out side bars and option letters.
	if !strings.HasPrefix(template, "/") {
		return nil, perr
	}
	lastSlash := strings.LastIndex(template, "/")
	if lastSlash == -1 {
		return nil, perr
	}
	opts := template[lastSlash+1:]
	if !regexp.MustCompile("[imsU]*").MatchString(opts) {
		return nil, perr
	}
	var prefix = ""
	if len(opts) > 0 {
		prefix = "(?" + opts + ")"
	}

	// Do variable interpolation.
	pattern := prefix + substitute(template[1:lastSlash], vars)

	// Build the regex.
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, NewProofError(keybase1.ProofStatus_INVALID_PVL,
			"Could not build regex (%v): %v", template, err)
	}
	return re, nil
}

// Substitute vars for %{name} in the string.
// Only substitutes whitelisted variables.
func substitute(template string, vars PvlScriptVariables) string {
	// Regex to find %{name} occurrences.
	re := regexp.MustCompile("%{\\w+}")
	substituteOne := func(vartag string) string {
		// TODO make vars only available for some proof services.
		// Strip off the %, {, and }
		varname := vartag[2 : len(vartag)-1]
		var value string
		switch varname {
		case "username_service":
			value = vars.UsernameService
		case "username_keybase":
			value = vars.UsernameKeybase
		case "sig":
			value = b64.StdEncoding.EncodeToString(vars.Sig)
		case "sig_id_medium":
			value = vars.SigIDMedium
		case "sig_id_short":
			value = vars.SigIDShort
		case "dns_proof_hostname":
			value = vars.DNSProofHostname
		default:
			// Unrecognized variable, do no substitution.
			return vartag
		}
		return regexp.QuoteMeta(value)
	}
	return re.ReplaceAllStringFunc(template, substituteOne)
}

func jsonHasKey(w *jsonw.Wrapper, key string) bool {
	return !w.AtKey(key).IsNil()
}

func stringToService(service string) (keybase1.ProofType, ProofError) {
	switch service {
	case "twitter":
		return keybase1.ProofType_TWITTER, nil
	case "github":
		return keybase1.ProofType_GITHUB, nil
	case "reddit":
		return keybase1.ProofType_REDDIT, nil
	case "coinbase":
		return keybase1.ProofType_COINBASE, nil
	case "hackernews":
		return keybase1.ProofType_HACKERNEWS, nil
	case "dns":
		return keybase1.ProofType_DNS, nil
	case "rooter":
		return keybase1.ProofType_ROOTER, nil
	case "web":
		return keybase1.ProofType_GENERIC_WEB_SITE, nil
	default:
		return 0, NewProofError(keybase1.ProofStatus_INVALID_PVL,
			"Unsupported service %v", service)
	}
}

func serviceToString(service keybase1.ProofType) (string, ProofError) {
	// This is not quite the same as RemoteServiceTypes due to http/https.
	// TODO but maybe it should be
	// TODO (not here) plain-http story.
	switch service {
	case keybase1.ProofType_TWITTER:
		return "twitter", nil
	case keybase1.ProofType_GITHUB:
		return "github", nil
	case keybase1.ProofType_REDDIT:
		return "reddit", nil
	case keybase1.ProofType_COINBASE:
		return "coinbase", nil
	case keybase1.ProofType_HACKERNEWS:
		return "hackernews", nil
	case keybase1.ProofType_DNS:
		return "dns", nil
	case keybase1.ProofType_ROOTER:
		return "rooter", nil
	case keybase1.ProofType_GENERIC_WEB_SITE:
		return "web", nil
	default:
		return "", NewProofError(keybase1.ProofStatus_INVALID_PVL,
			"Unsupported service %v", service)
	}
}

func init() {
	// TODO replace this init with loading from gocode

	usr, err := user.Current()
	if err != nil {
		log.Panic(err)
	}
	relpath := "go/src/github.com/keybase/client/go/libkb/pvl_hardcoded.json"
	path := fmt.Sprintf("%v/%v", usr.HomeDir, relpath)
	data, err := ioutil.ReadFile(path)
	if err != nil {
		log.Panicf("could not read pvl json file %v: %v", path, err)
	}
	wrapper, err := jsonw.Unmarshal(data)
	if err != nil {
		log.Panicf("could not read pvl json file %v: %v", path, err)
	}
	hardcodedPVL = *wrapper
}
