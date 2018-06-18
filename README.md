# goircd

Ronsor goircd is an IRC server written in Go!

Currently supported:

* Linking with other servers
* IRC operators (and /KILL)
* Channel modes: +ntms
* Channel bans and excepts (+b and +e)
* Channel kicks
* Most common commands (JOIN, PART, QUIT, NICK, PRIVMSG/NOTICE, WHOIS, WHO, LINKS, etc.)

Not yet supported:

* GZIP links (broken)
* INVITE
* Probably other stuff

## getting

Use `go get`: `go get git.ronsor.pw/ronsor/goircd`

## test server

Connect to hub.ronsor.eu.org, port 6667, or 6697 for TLS

## setup

1. copy example.conf to ircd.conf and start reading!
2. start goircd: ./goircd
