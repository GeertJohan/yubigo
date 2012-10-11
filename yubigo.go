package yubigo

import (
	"errors"
)

type YubiAuth struct {
	id          string
	key         string
	url         string
	url_list    []string
	url_index   int
	lastquery   string
	response    string
	https       bool
	httpsverify bool
}

func NewYubiAuth(id string, key string) {
	auth := &YubiAuth{
		id:          id,
		key:         key,
		https:       true,
		httpsverify: true,
	}
}
