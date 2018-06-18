package main

import (
	"io/ioutil"
	"strings"
)

func getmotd() []string {
	i, _ := ioutil.ReadFile(confdata.Server.MOTD)
	if i == nil {
		return []string{"OOPS! I'm missing a MOTD file"}
	}
	return strings.Split(string(i),"\n")
}
