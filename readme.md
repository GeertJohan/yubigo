
## yubigo

Yubigo is a Yubikey client API library that provides an easy way to integrate the Yubico Yubikey into your existing Go-based user authentication infrastructure.

### Status and Roadmap

This package is very young and lacks automated tests and documentation. Development is high.

At this moment there is **no guarantee** regarding the stability of this package. Although this package is already being used in a production environment.
Everything is subject to change.

Development is co-ordinated via this github repository. If you made an improvement, please request for pull!

This project is licensed under a Simplified BSD license. Please read the [LICENSE file][license].

#### Todo
 - parallel connection
 - removing the usage of a map in Verify()
 - test files
 - more documentation

### Installation

Installation is simple. Use go get:
`go get github.com/GeertJohan/yubigo`

This github repository has a tag `go1`. `go get` will download the revision on that tag. The revision at the `go1` tag is the latest stable revision available.

### Usage

Make sure to import the package: `import "github.com/GeertJohan/yubigo"`

For use with the default Yubico servers, make sure you have an API key. [Request a key][getapikey].

**Basic OTP checking usage:**
```go

// create a new yubiAuth instance with id and key
yubiAuth, err := yubigo.NewYubiAuth("1234", "fdsaffqaf4vrc2q3cds=")
if err != nil {
	// probably an invalid key was given
	log.Fatalln(err)
}

// verify an OTP value
result, ok, err := yubiAuth.Verify("ccccccbetgjevivbklihljgtbenbfrefccveiglnjfbc")
if err != nil {
	log.Fatalln(err)
}

if ok {
	// succes!! The OTP is valid!
	// lets get some data from the result
	sessioncounter := result.GetParameter("sessioncounter")
	log.Printf("This was the  %sth time the Yubikey was pluggin into a computer.\n", sessioncounter)
} else {
	// fail! The OTP is invalid or has been used before.
	log.Println("The given OTP is invalid!!!")
}
```


**Do not verify HTTPS certificate:**
```go
// Disable HTTPS cert verification. Use true to enable again.
yubiAuth.VerifyHttps(false)
```


**HTTP instead of HTTPS:**
```go
// Disable HTTPS. Use true to enable again.
yubiAuth.UseHttps(false)
```


**Custom API server:**
```go
// Set a list of n servers, each server as host + path. 
// Do not prepend with protocol
yubiAuth.SetApiServerList("api0.server.com/api/verify", "api1.server.com/api/verify", "otherserver.com/api/verify")
```


### Extra information

This project is implementing a pure-Go Yubico OTP Validation Client following the [Validation Protocol Version 2.0][validationProtocolV20].

[Package contents documentation at go.pkgdoc.org][pkgdoc]


 [license]: https://github.com/GeertJohan/yubigo/blob/master/LICENSE
 [getapikey]: https://upgrade.yubico.com/getapikey/
 [pkgdoc]: http://go.pkgdoc.org/github.com/GeertJohan/yubigo
 [validationProtocolV20]: http://code.google.com/p/yubikey-val-server-php/wiki/ValidationProtocolV20