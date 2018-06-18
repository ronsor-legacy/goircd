package main

import (
	"os"
	"io/ioutil"
	"log"
	"flag"
	"strings"
	"crypto/tls"
	"github.com/hashicorp/hcl"
	"net"
	"github.com/kabukky/httpscerts"
)

var conffile = flag.String("c", "ircd.conf", "IRCd configuration file")
var confdata *Config
var shutdown = make(chan error)
var SNO = map[string]string{
	"LINK":"l",
	"CLIENT":"c",
	"INFO":"i",
	"FATAL":"f",
	"WARN":"w",
	"ERROR":"e",
	"DEBUG":"d",
}
type LogWriter struct {}

func (l *LogWriter) Write(line []byte) (int, error) {
	os.Stderr.Write(line)
	line2 := string(line[:len(line)-1])
	l2x := strings.Split(line2, " ")
	line2 = strings.Replace(line2, l2x[0] + " " + l2x[1] + " " + l2x[2] + " ", "", 1)
	typ := l2x[2]
	for t := range clients.IterBuffered() {
		cl := t.Val.(*Client)
		if cl.Oper && !cl.Remote && strings.Contains(cl.SNO, SNO[typ]) {
			cl.Conn.Encode(M(mypfx(), "NOTICE", cl.Nick, "*** " + line2))
		}
	}
	return len(line), nil
}
func readconf() {
	x, e := ioutil.ReadFile(*conffile)
	if e != nil {
		log.Println("WARN", "Can't read configuration:", e)
		return
	}
	var c Config
	e = hcl.Unmarshal(x, &c)
	if e != nil {
		log.Println("WARN", "Can't read configuration:", e)
		return
	}
	confdata = &c
}
var tlsconf = &tls.Config{InsecureSkipVerify: true}
func main() {
	flag.Parse()
	readconf()
	if confdata == nil {
		log.Fatalln("FATAL", "I need a valid configuration file.")
	}
	log.Println("INFO", "I am", confdata.Server.Name, "listening on", len(confdata.Listen), "ports")
	if confdata.TLS.Cert != "" {
		again:
		cert, err := tls.LoadX509KeyPair(confdata.TLS.Cert, confdata.TLS.Key)
		if err != nil {
			log.Println("INFO", "Generating TLS certificates...")
			err = httpscerts.Generate(confdata.TLS.Cert, confdata.TLS.Key, confdata.Server.Name)
			if err != nil {
				log.Fatalln("FATAL", "TLS:", err)
			}
			goto again
		}
		tlsconf.Certificates = []tls.Certificate{cert}
	}
	for k, v := range confdata.Listen {
		var err error
		lstn := net.Listener(nil)
		v.Address = k
		if !v.TLS {
			lstn, err = net.Listen("tcp", v.Address)
			if err != nil {
				log.Println("WARN", "Failed to listen on", "(" + v.Address + "):", err)
				continue
			}
			log.Println("INFO", "Listening on " + v.Address)
		} else {
			lstn, err = tls.Listen("tcp", v.Address, tlsconf)
			if err != nil {
				log.Println("WARN", "Failed to listen on", "(" + v.Address + "):", err)
				continue
			}
			log.Println("INFO", "TLS: Listening on " + v.Address)
		}
		go func() {
			for {
				conn, err := lstn.Accept()
				if err != nil {
					log.Println("DEBUG", "Failed to accept():", err)
					continue
				}
				go client(conn,false,nil)
			}
		} ()
	}
	log.SetOutput(new(LogWriter))
	for k, v := range confdata.Link {
		if v.Auto {
			go ConnectServer(k, v.Address, v.TLS)
		}
	}
	<- shutdown
}
