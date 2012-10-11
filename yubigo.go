package yubigo

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	httpUserAgent = "github.com/GeertJohan/yubigo"
)

var (
	dvorakToQwerty = strings.NewReplacer(
		"j", "c", "x", "b", "e", "d", ".", "e", "u", "f", "i", "g", "d", "h", "c", "i",
		"h", "j", "t", "k", "n", "l", "b", "n", "p", "r", "y", "t", "g", "u", "k", "v",
		"J", "C", "X", "B", "E", "D", ".", "E", "U", "F", "I", "G", "D", "H", "C", "I",
		"H", "J", "T", "K", "N", "L", "B", "N", "P", "R", "Y", "T", "G", "U", "K", "V")
	matchDvorak     = regexp.MustCompile(`^[jxe.uidchtnbpygkJXE.UIDCHTNBPYGK]{32,48}$`)
	matchQwerty     = regexp.MustCompile(`^[cbdefghijklnrtuvCBDEFGHIJKLNRTUV]{32,48}$`)
	signatureUrlFix = regexp.MustCompile(`\+`)
)

// Parse input string into yubikey prefix, ciphertext
func ParseOTP(otp string) (prefix string, ciphertext string, err error) {
	if len(otp) < 32 || len(otp) > 48 {
		err = errors.New("OTP has wrong length.")
		return
	}

	// When otp matches dvorak-otp, then translate to qwerty.
	if matchDvorak.MatchString(otp) {
		otp = dvorakToQwerty.Replace(otp)
	}

	// Verify that otp matches qwerty expectations
	if !matchQwerty.MatchString(otp) {
		err = errors.New("Given string is not a valid Yubikey OTP. It contains invalid characters and/or the length is wrong.")
		return
	}

	l := len(otp)
	prefix = otp[0 : l-32]
	ciphertext = otp[l-32 : l]
	return
}

type YubiAuth struct {
	id                string
	key               []byte
	apiServerList     []string
	protocol          string
	verifyCertificate bool
	client            *http.Client
}

// Create a yubiAuth instance with given id and key.
// Uses defaults for all other values
func NewYubiAuth(id string, key string) (auth *YubiAuth, err error) {
	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		err = errors.New(fmt.Sprintf("Given key seems to be invalid. Could not base64_decode. Error: %s\n", err))
		return
	}

	auth = &YubiAuth{
		id:  id,
		key: keyBytes,

		apiServerList: []string{"api.yubico.com/wsapi/2.0/verify",
			"api2.yubico.com/wsapi/2.0/verify",
			"api3.yubico.com/wsapi/2.0/verify",
			"api4.yubico.com/wsapi/2.0/verify",
			"api5.yubico.com/wsapi/2.0/verify"},

		protocol:          "https://",
		verifyCertificate: true,
	}
	auth.buildHttpClient()
	return
}

func (ya *YubiAuth) buildHttpClient() {
	tlsConfig := &tls.Config{}
	if !ya.verifyCertificate {
		tlsConfig.InsecureSkipVerify = true
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	ya.client = &http.Client{
		Transport: transport,
	}
}

// Use this method to specify a different server(s) for verification.
// Each url should look like this: "api.yubico.com/wsapi/verify".
// A verify call tries the first url, and uses the following url(s) as failover.
// There is no loadbalancing involved.
func (ya *YubiAuth) SetApiServerList(url ...string) {
	ya.apiServerList = url
}

// Retrieve the server url's that are being used for verification.
func (ya *YubiAuth) GetApiServerList() []string {
	return ya.apiServerList
}

// Setter
func (ya *YubiAuth) UseHttps(useHttps bool) {
	if useHttps {
		ya.protocol = "https://"
	} else {
		ya.protocol = "http://"
	}
}

// Setter
func (ya *YubiAuth) HttpsVerifyCertificate(verifyCertificate bool) {
	ya.verifyCertificate = verifyCertificate
	ya.buildHttpClient()
}

func (ya *YubiAuth) Verify(otp string) (yr *YubiResponse, ok bool, err error) {
	// check the OTP
	_, _, err = ParseOTP(otp)
	if err != nil {
		return nil, false, err
	}

	// create map to store parameters for this verification request
	params := make(map[string]string)
	params["id"] = ya.id
	params["otp"] = otp

	// Create 40 characters nonce
	rand.Seed(time.Now().UnixNano())
	k := make([]rune, 40)
	for i := 0; i < 40; i++ {
		c := rand.Intn(35)
		if c < 10 {
			c += 48 // numbers (0-9) (0+48 == 48 == '0', 9+48 == 57 == '9')
		} else {
			c += 87 // lower case alphabets (a-z) (10+87 == 97 == 'a', 35+87 == 122 = 'z')
		}
		k[i] = rune(c)
	}
	nonce := string(k)
	params["nonce"] = nonce

	// hardcoded in the library for now.
	//++ TODO(GeertJohan): add these values to the yubiAuth object and create getters/setters
	params["timestamp"] = "1"
	params["sl"] = "secure"
	//++ TODO(GeertJohan): Add timeout support
	//params["timeout"] = "" 

	// create slice from map containing key=value
	//++?? Why use a map anyway? Maybe just use slice for the complere process..
	paramSlice := make([]string, 0, len(params))
	for key, value := range params {
		paramSlice = append(paramSlice, key+"="+value)
	}

	// sort the slice
	sort.Strings(paramSlice)

	// create parameter string
	paramString := strings.Join(paramSlice, "&")

	// generate signature
	if len(ya.key) > 0 {
		hmacenc := hmac.New(sha1.New, ya.key)
		_, err := hmacenc.Write([]byte(paramString))
		if err != nil {
			return nil, false, errors.New(fmt.Sprintf("Could not calculate signature. Error: %s\n", err))
		}
		signature := base64.StdEncoding.EncodeToString(hmacenc.Sum([]byte{}))
		signature = signatureUrlFix.ReplaceAllString(signature, `%2B`)
		paramString = paramString + "&h=" + signature
	}

	// loop through server list (simple but effective api server failover)
	for _, apiServer := range ya.apiServerList {

		url := ya.protocol + apiServer + "?" + paramString

		request, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, false, errors.New(fmt.Sprintf("Could not create http request. Error: %s\n", err))
		}
		request.Header.Add("User-Agent", httpUserAgent)

		result, err := ya.client.Do(request)
		if err != nil {
			// that didn't work, now failover!
			continue
		}

		bodyReader := bufio.NewReader(result.Body)
		yr = &YubiResponse{}
		yr.parameters = make(map[string]string)
		yr.query = paramString
		for {
			// read through the response lines
			line, err := bodyReader.ReadString('\n')

			// handle error, which at one point should be an expected io.EOF (end of file)
			if err != nil {
				if err == io.EOF {
					break // successfully done with reading lines, lets break this for loop
				}
				return nil, false, errors.New(fmt.Sprintf("Could not read result body from the server. Error: %s\n", err))
			}

			// parse result lines, split on first '=', trim \n and \r
			keyvalue := strings.SplitN(line, "=", 2)
			if len(keyvalue) == 2 {
				yr.parameters[keyvalue[0]] = strings.Trim(keyvalue[1], "\n\r")
			}
		}

		// check status
		status, ok := yr.parameters["status"]
		if !ok || status != "OK" {
			switch status {
			case "BAD_OTP":
				return yr, false, nil
			case "REPLAYED_OTP":
				return yr, false, nil
			case "BAD_SIGNATURE":
				return yr, false, errors.New("Signature verification at the api server failed. The used id/key combination could be invalid or is not activated (yet).")
			case "NO_SUCH_CLIENT":
				return yr, false, errors.New("The api server does not accept the given id. It might be invalid or is not activated (yet).")
			case "OPERATION_NOT_ALLOWED":
				return yr, false, errors.New("The api server does not allow the given api id to verify OTPs.")
			case "BACKEND_ERROR":
				return yr, false, errors.New("The api server seems to be broken. Please contact the api servers system administration (yubico servers? contact yubico).")
			case "NOT_ENOUGH_ANSWERS":
				return yr, false, errors.New("The api server could not get requested number of syncs during before timeout")
			case "REPLAYED_REQUEST":
				return yr, false, errors.New("The api server has seen this unique request before. If you receive this error, you might be the victim of a man-in-the-middle attack.")
			default:
				return yr, false, errors.New(fmt.Sprintf("Unknown status parameter (%s) sent by api server.", status))
			}
		}

		// check otp
		otpCheck, ok := yr.parameters["otp"]
		if !ok || otp != otpCheck {
			return nil, false, errors.New("Could not validate otp value from server response.")
		}

		// check nonce
		nonceCheck, ok := yr.parameters["nonce"]
		if !ok || nonce != nonceCheck {
			return nil, false, errors.New("Could not validate nonce value from server response.")
		}

		// check attached signature with remake of that signature, if key is actually in use.
		if len(ya.key) > 0 {
			receivedSignature, ok := yr.parameters["h"]
			if !ok || len(receivedSignature) == 0 {
				return nil, false, errors.New("No signature hash was attached by the api server, we do expect one though. This might be a hacking attempt.")
			}

			// create a slice with the same size-1 as the parameters map (we're leaving the hash itself out of it's replica calculation)
			receivedValuesSlice := make([]string, 0, len(yr.parameters)-1)
			for key, value := range yr.parameters {
				if key != "h" {
					receivedValuesSlice = append(receivedValuesSlice, key+"="+value)
				}
			}
			sort.Strings(receivedValuesSlice)
			receivedValuesString := strings.Join(receivedValuesSlice, "&")
			hmacenc := hmac.New(sha1.New, ya.key)
			_, err := hmacenc.Write([]byte(receivedValuesString))
			if err != nil {
				return nil, false, errors.New(fmt.Sprintf("Could not calculate signature replica. Error: %s\n", err))
			}
			recievedSignatureReplica := base64.StdEncoding.EncodeToString(hmacenc.Sum([]byte{}))

			if receivedSignature != recievedSignatureReplica {
				return nil, false, errors.New("The received signature hash is not valid. This might be a hacking attempt.")
			}
		}

		// we're done!
		yr.ok = true
		return yr, true, nil
	}

	return nil, false, errors.New("None of the api servers responded. Could not verify OTP")
}

type YubiResponse struct {
	query      string
	parameters map[string]string
	ok         bool
}

func (yr *YubiResponse) IsOk() bool {
	return yr.ok
}

// Get the query used for this YubiResponse.
func (yr *YubiResponse) GetQuery() string {
	return yr.query
}

// Retrieve a parameter (as sent by the api server)
func (yr *YubiResponse) GetParameter(key string) (value string) {
	value, ok := yr.parameters[key]
	if !ok {
		value = ""
	}
	return value
}
