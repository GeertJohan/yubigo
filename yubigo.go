package main

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var (
	dvorakToQwerty = strings.NewReplacer(
		"j", "c", "x", "b", "e", "d", ".", "e", "u", "f", "i", "g", "d", "h", "c", "i",
		"h", "j", "t", "k", "n", "l", "b", "n", "p", "r", "y", "t", "g", "u", "k", "v",
		"J", "C", "X", "B", "E", "D", ".", "E", "U", "F", "I", "G", "D", "H", "C", "I",
		"H", "J", "T", "K", "N", "L", "B", "N", "P", "R", "Y", "T", "G", "U", "K", "V")
	matchDvorak = regexp.MustCompile(`^[jxe.uidchtnbpygkJXE.UIDCHTNBPYGK]{32,48}$`)
	matchQwerty = regexp.MustCompile(`^[cbdefghijklnrtuvCBDEFGHIJKLNRTUV]{32,48}$`)
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
	id          string
	key         string
	url_list    []string
	url_index   int
	https       bool
	httpsverify bool
}

type yubiResponse struct {
	query      string
	response   string
	parameters map[string]string
	ok         bool
}

// Create a yubiAuth instance with given id and key.
// Uses defaults for all other values
func NewYubiAuth(id string, key string) (auth *yubiAuth) {
	auth = &yubiAuth{
		id:  id,
		key: key,

		url_list: []string{"api.yubico.com/wsapi/2.0/verify",
			"api2.yubico.com/wsapi/2.0/verify",
			"api3.yubico.com/wsapi/2.0/verify",
			"api4.yubico.com/wsapi/2.0/verify",
			"api5.yubico.com/wsapi/2.0/verify"},
		url_index: 0,

		https:       true,
		httpsverify: true,
	}
	return
}

// Use this method to specify a different URL for verification.
// This method accepts multiple url's for failover.
// The default is "api.yubico.com/wsapi/verify".
func (ya *yubiAuth) SetUrlList(url ...string) {
	ya.url_list = url
}

// Retrieve the url's that are being used for verification.
func (ya *yubiAuth) GetUrlList() []string {
	return ya.url_list
}

// Get a url from the url_list. Increments on each call. Used for API failover.
func (ya *yubiAuth) getNextUrl() (string, error) {
	if ya.url_index >= len(ya.url_list) {
		return "", errors.New("No next url available.")
	}

	url := ya.url_list[ya.url_index]
	ya.url_index++
	return url, nil
}

// Reset the url index thats being used for API failover.
func (ya *yubiAuth) resetNextUrl() {
	ya.url_index = 0
}

func (ya *yubiAuth) Verify(otp string) (yr *yubiResponse, ok bool, err error) {
	/* Construct parameters string */
	// $ret = $this->parsePasswordOTP($token);
	// if (!$ret) {
	// return PEAR::raiseError('Could not parse Yubikey OTP');
	// }
	// $params = array('id'=>$this->_id,
	// 'otp'=>$ret['otp'],
	// 'nonce'=>md5(uniqid(rand())));
	// /* Take care of protocol version 2 parameters */
	// if ($use_timestamp) $params['timestamp'] = 1;
	// if ($sl) $params['sl'] = $sl;
	// if ($timeout) $params['timeout'] = $timeout;
	// ksort($params);
	// $parameters = '';
	// foreach($params as $p=>$v) $parameters .= "&" . $p . "=" . $v;
	// $parameters = ltrim($parameters, "&");

	// /* Generate signature. */
	// if($this->_key <> "") {
	// $signature = base64_encode(hash_hmac('sha1', $parameters,
	// $this->_key, true));
	// $signature = preg_replace('/\+/', '%2B', $signature);
	// $parameters .= '&h=' . $signature;
	// }

	// /* Generate and prepare request. */
	// $this->_lastquery=null;
	// $this->URLreset();
	// $mh = curl_multi_init();
	// $ch = array();
	// while($URLpart=$this->getNextURLpart())
	// {
	// /* Support https. */
	// if ($this->_https) {
	// $query = "https://";
	// } else {
	// $query = "http://";
	// }
	// $query .= $URLpart . "?" . $parameters;

	// if ($this->_lastquery) { $this->_lastquery .= " "; }
	// $this->_lastquery .= $query;

	// $handle = curl_init($query);
	// curl_setopt($handle, CURLOPT_USERAGENT, "PEAR Auth_Yubico");
	// curl_setopt($handle, CURLOPT_RETURNTRANSFER, 1);
	// if (!$this->_httpsverify) {
	// curl_setopt($handle, CURLOPT_SSL_VERIFYPEER, 0);
	// }
	// curl_setopt($handle, CURLOPT_FAILONERROR, true);
	// /* If timeout is set, we better apply it here as well
	// in case the validation server fails to follow it.
	// */
	// if ($timeout) curl_setopt($handle, CURLOPT_TIMEOUT, $timeout);
	// curl_multi_add_handle($mh, $handle);

	// $ch[$handle] = $handle;
	// }

	// /* Execute and read request. */
	// $this->_response=null;
	// $replay=False;
	// $valid=False;
	// do {
	// /* Let curl do its work. */
	// while (($mrc = curl_multi_exec($mh, $active))
	// == CURLM_CALL_MULTI_PERFORM)
	// ;

	// while ($info = curl_multi_info_read($mh)) {
	// if ($info['result'] == CURLE_OK) {

	// /* We have a complete response from one server. */

	// $str = curl_multi_getcontent($info['handle']);
	// $cinfo = curl_getinfo ($info['handle']);

	// if ($wait_for_all) { # Better debug info
	// $this->_response .= 'URL=' . $cinfo['url'] ."\n"
	// . $str . "\n";
	// }

	// if (preg_match("/status=([a-zA-Z0-9_]+)/", $str, $out)) {
	// $status = $out[1];

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
	return
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
	a, b, err := ParseOTP("enter an OTP here...")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(a)
	fmt.Println(b)
}
