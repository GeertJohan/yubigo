package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
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

type yubiAuth struct {
	id            string
	key           []byte
	apiServerList []string
	protocol      string
	httpsVerify   bool
	client        *http.Client
}

type yubiResponse struct {
	query      string
	response   string
	parameters map[string]string
	ok         bool
}

// Create a yubiAuth instance with given id and key.
// Uses defaults for all other values
func NewYubiAuth(id string, key string) (auth *yubiAuth, err error) {
	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		err = errors.New(fmt.Sprintf("Given key seems to be invalid. Could not base64_decode. Error: %s\n", err))
		return
	}

	auth = &yubiAuth{
		id:  id,
		key: keyBytes,

		apiServerList: []string{"api.yubico.com/wsapi/2.0/verify",
			"api2.yubico.com/wsapi/2.0/verify",
			"api3.yubico.com/wsapi/2.0/verify",
			"api4.yubico.com/wsapi/2.0/verify",
			"api5.yubico.com/wsapi/2.0/verify"},

		protocol:    "https://",
		httpsVerify: true,
	}
	auth.buildHttpClient()
	return
}

func (ya *yubiAuth) buildHttpClient() {
	tlsConfig := &tls.Config{}
	if !ya.httpsVerify {
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
func (ya *yubiAuth) SetApiServerList(url ...string) {
	ya.apiServerList = url
}

// Retrieve the server url's that are being used for verification.
func (ya *yubiAuth) GetApiServerList() []string {
	return ya.apiServerList
}

// Setter
func (ya *yubiAuth) UseHttps(useHttps bool) {
	if useHttps {
		ya.protocol = "https://"
	} else {
		ya.protocol = "http://"
	}
}

// Setter
func (ya *yubiAuth) VerifyHttps(verifyHttps bool) {
	ya.httpsVerify = verifyHttps
	ya.buildHttpClient()
}

func (ya *yubiAuth) Verify(otp string) (yr *yubiResponse, ok bool, err error) {
	// check and parse the otp
	prefix, ciphertext, err := ParseOTP(otp)
	if err != nil {
		return nil, false, err
	}
	log.Printf("prefix: %s\n", prefix)
	log.Printf("ciphertext: %s\n", ciphertext)

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
	params["nonce"] = string(k)

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
	log.Printf("paramString: %s\n", paramString)

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
	log.Printf("paramString: %s\n", paramString)

	// loop through server list (automatic failover)
	for _, apiServer := range ya.apiServerList {

		url := ya.protocol + apiServer + "?" + paramString
		log.Println("Will connect to: ", url)

		request, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, false, errors.New(fmt.Sprintf("Could not create http request. Error: %s\n", err))
		}
		request.Header.Add("User-Agent", httpUserAgent)

		result, err := ya.client.Do(request)
		if err != nil {
			log.Println("client err: ", err)
			continue
		}

		bodyReader := bufio.NewReader(result.Body)
		for {
			line, err := bodyReader.ReadString('\n')
			log.Printf("line: %s\n", line)
			if err != nil {
				if err == io.EOF {
					break
				}
				log.Print("Got error when reading string from body: %s\n", err)
				return nil, false, errors.New(fmt.Sprintf("Could not read result body from the server. Error: %s\n", err))
			}

			//++ do something with that line!!!
		}

		if true {
			log.Println("Done?")
			break
		}

	}

	// if (preg_match("/status=([a-zA-Z0-9_]+)/", $str, $out)) {
	// $status = $out[1];

	// /*
	// * There are 3 cases.
	// *
	// * 1. OTP or Nonce values doesn't match - ignore
	// * response.
	// *
	// * 2. We have a HMAC key. If signature is invalid -
	// * ignore response. Return if status=OK or
	// * status=REPLAYED_OTP.
	// *
	// * 3. Return if status=OK or status=REPLAYED_OTP.
	// */

	// if (!preg_match("/otp=".$params['otp']."/", $str) ||
	// !preg_match("/nonce=".$params['nonce']."/", $str)) {
	// /* Case 1. Ignore response. */
	// }
	// elseif ($this->_key <> "") {
	// /* Case 2. Verify signature first */
	// $rows = explode("\r\n", trim($str));
	// $response=array();
	// while (list($key, $val) = each($rows)) {
	// /* = is also used in BASE64 encoding so we only replace the first = by # which is not used in BASE64 */
	// $val = preg_replace('/=/', '#', $val, 1);
	// $row = explode("#", $val);
	// $response[$row[0]] = $row[1];
	// }

	// $parameters=array('nonce','otp', 'sessioncounter', 'sessionuse', 'sl', 'status', 't', 'timeout', 'timestamp');
	// sort($parameters);
	// $check=Null;
	// foreach ($parameters as $param) {
	// if (array_key_exists($param, $response)) {
	// if ($check) $check = $check . '&';
	// $check = $check . $param . '=' . $response[$param];
	// }
	// }

	// $checksignature =
	// base64_encode(hash_hmac('sha1', utf8_encode($check),
	// $this->_key, true));

	// if($response['h'] == $checksignature) {
	// if ($status == 'REPLAYED_OTP') {
	// if (!$wait_for_all) { $this->_response = $str; }
	// $replay=True;
	// }
	// if ($status == 'OK') {
	// if (!$wait_for_all) { $this->_response = $str; }
	// $valid=True;
	// }
	// }
	// } else {
	// /* Case 3. We check the status directly */
	// if ($status == 'REPLAYED_OTP') {
	// if (!$wait_for_all) { $this->_response = $str; }
	// $replay=True;
	// }
	// if ($status == 'OK') {
	// if (!$wait_for_all) { $this->_response = $str; }
	// $valid=True;
	// }
	// }
	// }
	// if (!$wait_for_all && ($valid || $replay))
	// {
	// /* We have status=OK or status=REPLAYED_OTP, return. */
	// foreach ($ch as $h) {
	// curl_multi_remove_handle($mh, $h);
	// curl_close($h);
	// }
	// curl_multi_close($mh);
	// if ($replay) return PEAR::raiseError('REPLAYED_OTP');
	// if ($valid) return true;
	// return PEAR::raiseError($status);
	// }

	// curl_multi_remove_handle($mh, $info['handle']);
	// curl_close($info['handle']);
	// unset ($ch[$info['handle']]);
	// }
	// curl_multi_select($mh);
	// }
	// } while ($active);

	// /* Typically this is only reached for wait_for_all=true or
	// * when the timeout is reached and there is no
	// * OK/REPLAYED_REQUEST answer (think firewall).
	// */

	// foreach ($ch as $h) {
	// curl_multi_remove_handle ($mh, $h);
	// curl_close ($h);
	// }
	// curl_multi_close ($mh);

	// if ($replay) return PEAR::raiseError('REPLAYED_OTP');
	// if ($valid) return true;
	// return PEAR::raiseError('NO_VALID_ANSWER');
	// }

	return nil, false, errors.New("None of the api servers responded. Could not verify OTP")
}

func (yr *yubiResponse) IsOk() bool {
	return yr.ok
}

// Get the query used for this yubiResponse.
func (yr *yubiResponse) GetQuery() string {
	return yr.query
}

// Get the last data received from the server, if any.
func (yr *yubiResponse) GetResponse() string {
	return yr.response
}

func (yr *yubiResponse) GetParameter(key string) (value string, ok bool) {
	//++ TODO(GeertJohan): do this stuff when getting the result in the request:
	// if ($parameters == null) {
	// 	$parameters = array('timestamp', 'sessioncounter', 'sessionuse');
	// }
	// $param_array = array();
	// foreach ($parameters as $param) {
	// 	if(!preg_match("/" . $param . "=([0-9]+)/", $this->_response, $out)) {
	// 		return PEAR::raiseError('Could not parse parameter ' . $param . ' from response');
	// 	}
	// 	$param_array[$param]=$out[1];
	// }
	// return $param_array;

	// This method simply wraps the yubiResponse.parameters map
	value, ok = yr.parameters[key]
	return
}

func main() {
	id := "9363"
	key := "7Anl+jXfPuBI+jPixmxxkxKKrX8="
	otp := "ccccccbfbcnbukughbkvgtkkvgtukfutdhfdrjjfeuhi"
	a, b, err := ParseOTP(otp)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(a)
	fmt.Println(b)

	ya, err := NewYubiAuth(id, key)
	if err != nil {
		log.Println("main err: ", err)
	}
	res, ok, err := ya.Verify(otp)
	if err != nil {
		log.Println("main err: ", err)
	}
	if ok {
		log.Println("main is ok!")
		log.Println(res)
	}
}
