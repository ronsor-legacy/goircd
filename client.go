package main

import (
	"github.com/ryanuber/go-glob"
	"crypto/sha256"
	"compress/gzip"
	"log"
	"gopkg.in/sorcix/irc.v2"
	"net"
	"fmt"
	"time"
	"github.com/orcaman/concurrent-map"
	"crypto/tls"
	"strings"
	"strconv"
)
func TS() string {
	return fmt.Sprintf("%d", time.Now().Unix())
}
type GzipConn struct {
	*gzip.Reader
	*gzip.Writer
}
func (g *GzipConn) Close() error {
	g.Writer.Close()
	g.Reader.Close()
	return nil
}
func strconvOr(a string, b int64) (c int64) {
	c, e := strconv.ParseInt(a, 0, 64)
	if e != nil {
		c = b
	}
	return
}
var clients = cmap.New()
func _O(a interface{}, _ bool) interface{} {
	return a
}
func M(p *irc.Prefix, c string, a ...string) *irc.Message {
	return &irc.Message{p,c,a}
}
func mypfx() *irc.Prefix {
	return &irc.Prefix{Name:confdata.Server.Name}
}
type Target interface {
	Message(*Client, string, string)
}
func ClientCount(flags string) int {
	num := 0
	for t := range clients.IterBuffered() {
		cl := t.Val.(*Client)
		if cl.Remote && strings.Contains(flags, "!r") { continue }
		if !cl.Remote && strings.Contains(flags, "+r") { continue }
		if cl.Oper && strings.Contains(flags, "!o") { continue }
		if !cl.Oper && strings.Contains(flags, "+o") { continue }
		if !cl.TLS && strings.Contains(flags, "+S") { continue }
		if cl.TLS && strings.Contains(flags, "!S") { continue }
		if cl.Server && strings.Contains(flags, "!s") { continue }
		if !cl.Server && strings.Contains(flags, "+s") { continue }
		num++
	}
	return num
}
func SendLusers(cl *Client) {
	nlocal := ClientCount("!r!s")
	ntls := ClientCount("+S!r")
	nglobal := ClientCount("!s")
	noper := ClientCount("+o")
	nservers := ClientCount("+s")
	nlservers := ClientCount("+s!r")
	cl.Conn.Encode(M(mypfx(), "251", cl.Nick, fmt.Sprintf("There are %d users and %d invisible on %d servers.", 0, nglobal, nservers)))
	cl.Conn.Encode(M(mypfx(), "252", cl.Nick, fmt.Sprintf("%d", noper), "operators online"))
	cl.Conn.Encode(M(mypfx(), "254", cl.Nick, fmt.Sprintf("%d", channels.Count()), "channels formed"))
	cl.Conn.Encode(M(mypfx(), "255", cl.Nick, fmt.Sprintf("I have %d clients and %d servers.", nlocal, nlservers)))
	cl.Conn.Encode(M(mypfx(), "260", cl.Nick, fmt.Sprintf("%d", ntls), "clients using a secure connection"))
	cl.Conn.Encode(M(mypfx(), "265", cl.Nick, fmt.Sprintf("%d", nlocal), fmt.Sprintf("%d", nlocal), fmt.Sprintf("Current local users %d, max %d", nlocal, nlocal)))
	cl.Conn.Encode(M(mypfx(), "266", cl.Nick, fmt.Sprintf("%d", nglobal), fmt.Sprintf("%d", nglobal), fmt.Sprintf("Current global users %d, max %d", nglobal, nglobal)))
}
func SendToAllServersButOne(cl *Client, m *irc.Message) {
	for t := range clients.IterBuffered() {
		tgt := t.Val.(*Client)
		if cl != nil && tgt.Conn == cl.Conn {
			continue
		}
		if tgt.Remote || !tgt.Server {
			continue
		}
		if m.Prefix != nil {
			m2 := *m
			m = &m2
			m.Prefix = &irc.Prefix{Name:m.Prefix.Name}
		}
		tgt.Conn.Encode(m)
	}
}
func FindTarget(s string) Target {
	ch, ok := channels.Get(strings.ToLower(s))
	if ok { return ch.(*Channel) }
	return ClientByNick(s)
}
func FindChannel(s string) *Channel {
	ch, ok := channels.Get(strings.ToLower(s))
	if ok { return ch.(*Channel) }
	return nil
}
type Client struct {
	Nick, User, Host, IP string
	InCommand chan *irc.Message
	Real string
	TS int64
	SNO string
	Introduce, TLS bool
	Remote, Server, Oper bool
	ServerName string
	Conn *irc.Conn
	RawConn net.Conn
	ID string
	Channels []*Channel
}
func ConnectServer(sname, addr string, usetls bool) {
	if !usetls {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			log.Println("LINK", "Failed to link server " + sname + ": " + err.Error())
			return
		}
		client(conn,true,confdata.Link[sname])
	} else {
		conn, err := tls.Dial("tcp", addr, tlsconf)
		if err != nil {
			log.Println("LINK", "Failed to link server " + sname + ": " + err.Error())
			return
		}
		client(conn,true,confdata.Link[sname])
	}
}
func (cl2 *Client) Flags() (flags string) {
	flags = "+i"
	if cl2.Server { flags += "S" }
	if cl2.Remote { flags += "R" }
	if cl2.Oper { flags += "o" }
	if cl2.TLS { flags += "z" }
	return
}
func (c *Client) Prefix() *irc.Prefix {
	if c.Server {
		return &irc.Prefix{Name: c.Nick}
	}
	return &irc.Prefix{c.Nick, c.User, c.Host}
}
func (c *Client) Kill(m string) {
	if c.Remote {
		c.Conn.Encode(M(mypfx(), "KILL", c.Nick, m))
		return
	}
	c.Quit(m)
}
func (c *Client) Quit(m string) {
	some := map[string]struct{}{}
	for _, v := range c.Channels {
		v.Quit(c,some,m)
		if v.Users.Count() == 0 { channels.Remove(strings.ToLower(v.Name)) }

	}
	SendToAllServersButOne(c, M(c.Prefix(), "QUIT", m))
	if c.Remote { clients.Remove(c.ID); return }
	log.Println("CLIENT", "Client quit:", c.Nick + "!" + c.User + "@" + c.Host + ":", m)
	if c.Server {
		log.Println("LINK", "Server quit:", c.Nick)
		for t := range clients.IterBuffered() {
			rc := t.Val.(*Client)
			if rc == c { continue }
			if rc.Conn == c.Conn && rc.Remote {
				rc.Quit(rc.ServerName + " " + confdata.Server.Name)
			}
		}
	}
	c.Conn.Encode(M(mypfx(), "ERROR", "Closing Link: " + m))
	c.RawConn.Close()
	c.ID = ""
}
func (c *Client) Message(src *Client, cmd, m string) {
	pfx := src.Prefix()
	if c.Remote {
		pfx = &irc.Prefix{Name:pfx.Name}
	}
	c.Conn.Encode(M(pfx, cmd, c.Nick, m))
}
func ClientByNick(s string) *Client {
	for t := range clients.IterBuffered() {
		cln := t.Val.(*Client)
		if strings.ToLower(cln.Nick) == strings.ToLower(s) {
			return cln
		}
	}
	return nil
}
func client(nc net.Conn, issc bool, lb *LinkBlock) {
	ISUPPORT := []string{"", "GZIP", "TLS=12", "NICKLEN=31", "PREFIX=(qaohv)~&@%+", "CHARSET=utf8", "TOPICLEN=307", "NETWORK="+confdata.Server.Network}
	ip, _, _ := net.SplitHostPort(nc.RemoteAddr().String())
	host := ip
	conn := irc.NewConn(nc)
	cl := &Client{ID: uniqid(), Host: host, IP: ip, Conn: conn, RawConn: nc, ServerName: confdata.Server.Name, TS: time.Now().Unix(), InCommand: make(chan *irc.Message, 32)}
	clients.Set(cl.ID, cl)
	quit := ""
	_, cl.TLS = nc.(*tls.Conn)
	_ = cl
	for k, v := range confdata.Spoof {
		if glob.Glob(k, cl.Nick + "!" + cl.User + "@" + cl.Host) {
			cl.Host = v.Spoof
		}
	}
	if issc {
		cl.Server = true
		cl.Introduce = true
		/*conn.Encode(M(nil, "CAP", "GZIP"))
		msg, err := conn.Decode()
		if msg == nil || err == nil {

		}
		if msg.Command == "801" {
			log.Println("DEBUG", "GZIP link to remote server initialized")
			rdr, err := gzip.NewReader(nc)
			if err != nil {
				quit = "Internal error"
				log.Println("DEBUG", "GZIP", err)
				return
			}
			rw := &GzipConn{rdr,gzip.NewWriter(nc)}
			conn = irc.NewConn(rw)
			cl.Conn = conn
		}*/
		conn.Encode(M(nil, "PASS", lb.Password))
		conn.Encode(M(nil, "PROTOCTL", "NOQUIT", "NICKIP", "NICKv2"))
		conn.Encode(M(nil, "SERVER", confdata.Server.Name, "1", confdata.Server.Description))
	}
	for {
		msg, err := conn.Decode()
		if cl.Server { log.Println("SDEBUG", msg) }
		if err != nil {
			quit = err.Error()
			break
		}
		if msg == nil { continue }
		curcl := cl
		if msg.Prefix != nil && msg.Prefix.Name != "" {
			curcl = ClientByNick(msg.Prefix.Name)
			if curcl == nil || curcl.Conn != cl.Conn {
				continue
			}
		}
		if cl.User == "" || cl.Nick == "" {
			if msg.Command == "NICK" && len(msg.Params) == 1 {
				if strings.ContainsAny(msg.Params[0], "! @.:") || ClientByNick(msg.Params[0]) != nil {
					conn.Encode(M(mypfx(),"433","*",msg.Params[0],"Nickname in use"))
					continue
				}
				cl.Nick = msg.Params[0]
				goto tryreg
			}
			if msg.Command == "SERVER" && len(msg.Params) == 3 {
				if ClientByNick(msg.Params[0]) != nil || strings.ToLower(msg.Params[0]) == strings.ToLower(confdata.Server.Name) {
					quit = "Server name collision"
					break
				}
				if !cl.Introduce {
					if lb && lb.Password != "" {
						conn.Encode(M(nil, "PASS", lb.Password))
					}
					conn.Encode(M(nil, "PROTOCTL", "NOQUIT", "NICKIP", "NICKv2"))
					conn.Encode(M(nil, "SERVER", confdata.Server.Name, "1", confdata.Server.Description))
					cl.Introduce = true
				}
				cl.Nick = msg.Params[0]
				cl.User = msg.Params[0]
				cl.Real = msg.Params[2]
				//cl.ServerName = cl.Nick
				cl.Server = true
				ISUPPORT[0] = cl.Nick
				for t := range clients.IterBuffered() {
					cl2 := t.Val.(*Client)
					if cl2.ID == cl.ID { continue }
					flags := cl2.Flags()

					//conn.Encode(M(nil, "CLIENT", cl2.Nick, cl2.User, cl2.Host, fmt.Sprintf("%d", cl2.TS), cl2.ServerName, flags, cl2.Real))
					if !cl2.Server {
					conn.Encode(M(nil, "NICK", cl2.Nick, "1", fmt.Sprintf("%d", cl2.TS), cl2.User, cl2.Host, cl2.ServerName, fmt.Sprintf("%d", cl2.TS), flags, "*", "*", cl2.Real))
					} else {
					conn.Encode(M(mypfx(), "SERVER", cl2.Nick, "2", cl2.Real))
					}
					for _, v := range cl2.Channels {
						conn.Encode(M(cl2.Prefix(), "JOIN", v.Name))
					}
				}
				for t := range channels.IterBuffered() {
					ch := t.Val.(*Channel)
					conn.Encode(M(mypfx(), "TOPIC", ch.Name, ch.Topic, TS()))
					conn.Encode(M(mypfx(), "MODE", ch.Name, "+" + ch.ModeFlags, TS()))
					for t2 := range ch.Status.IterBuffered() {
						for _, v := range t2.Val.([]byte) {
							xcl, _ := ch.Users.Get(t2.Key)
							if xcl == nil { continue }
							zcl := xcl.(*Client)
							if v > 0 {
								conn.Encode(M(mypfx(), "MODE", ch.Name, "+" + string(v), zcl.Nick, TS()))
							}
						}
					}
					for _, b := range ch.Bans {
						conn.Encode(M(mypfx(), "MODE", ch.Name, "+b", b, TS()))
					}
					for _, b := range ch.Excepts {
						conn.Encode(M(mypfx(), "MODE", ch.Name, "+e", b, TS()))
					}
				}
				log.Println("LINK", "New server linked:", cl.Nick)
				continue
			}
			if msg.Command == "CAP" && len(msg.Params) > 0 {
				if strings.Contains(msg.String(), "GZIP") {
					conn.Encode(M(mypfx(), "801", "*", "Go ahead with gzip compression"))
					rdr, err := gzip.NewReader(nc)
					if err != nil {
						quit = "Internal error"
						log.Println("DEBUG", "GZIP", err)
						break
					}
					rw := &GzipConn{rdr,gzip.NewWriter(nc)}
					conn = irc.NewConn(rw)
					cl.Conn = conn
				}
				continue
			}
			if msg.Command == "USER" && len(msg.Params) == 4 {
				cl.User = msg.Params[0]
				cl.Real = msg.Params[3]
				goto tryreg
			}
			conn.Encode(M(mypfx(),"451","*","Register first"))
			continue
			tryreg:
			if cl.User != "" && cl.Nick != "" {
				for k, v := range confdata.Ban {
					if glob.Glob(k, cl.Nick + "!" + cl.User + "@" + cl.Host) {
						quit = "Banned: " + v.Reason
						goto break2
					}
				}
				cl2 := cl
				SendToAllServersButOne(nil, M(nil, "NICK", cl2.Nick, "1", fmt.Sprintf("%d", cl2.TS), cl2.User, cl2.Host, cl2.ServerName, fmt.Sprintf("%d", cl2.TS), cl2.Flags(), "*", "*", cl2.Real))
				log.Println("CLIENT", "Client connecting:", cl.Nick + "!" + cl.User +"@" + cl.Host)
				conn.Encode(M(mypfx(), "001", cl.Nick, "Welcome to IRC!"))
				conn.Encode(M(mypfx(), "002", cl.Nick, "Your host is " + confdata.Server.Name + " running version 1.0"))
				ISUPPORT[0] = cl.Nick
				conn.Encode(M(mypfx(), "005", ISUPPORT...))
				SendLusers(cl)
				conn.Encode(M(mypfx(), "375", cl.Nick, "- " + confdata.Server.Name + " Message of the day - "))
				for _, v := range getmotd() {
					conn.Encode(M(mypfx(), "372", cl.Nick, "- " + v))
				}
				conn.Encode(M(mypfx(), "376", cl.Nick, "End of /MOTD reply"))
			}
			continue
		}
		NEED_PARAMS := M(mypfx(), "461", cl.Nick, msg.Command, "Need more parameters")
		switch msg.Command {
			case "LUSERS":
				SendLusers(cl)
			break
			case "LIST":
				i := 0
				pat := "*"
				if len(msg.Params) > 0 {
					pat = "*"+msg.Params[0]+"*"
				}
				for _, c := range channels.Keys() {
					if !glob.Glob(pat, c) { continue }
					if i > 100 { break }
					ch := FindChannel(c)
					if ch.HasFlag('s') { continue }
					conn.Encode(M(mypfx(), "322", cl.Nick, ch.Name, fmt.Sprintf("%d", ch.Users.Count()), ch.Topic))
				}
				conn.Encode(M(mypfx(), "323", cl.Nick, "End of RPL_LIST"))
			break
			case "SERVER":
				newcl := &Client{ID: uniqid(), Nick: msg.Params[0], User: msg.Params[0], Host: msg.Params[0], TS: time.Now().Unix(), ServerName: curcl.Nick,
					Real: msg.Params[2], TLS: false, Oper: false, Server: true, Remote: true,
					RawConn: cl.RawConn, Conn: cl.Conn, InCommand: make(chan *irc.Message, 32)}
				oldcl := ClientByNick(newcl.Nick)
				if oldcl != nil {
					quit = "Can't reintroduce server: " + newcl.Nick
					goto break2
				}
				SendToAllServersButOne(cl, msg)
				clients.Set(newcl.ID, newcl)

			break
			case "NICK":
				if cl.Server { goto CASE_NICK_SERVER }
				if true {
				if len(msg.Params) != 1 {
					conn.Encode(NEED_PARAMS)
					break
				}
				oldn := ClientByNick(msg.Params[0])
				if oldn != nil {
					conn.Encode(M(mypfx(),"433",curcl.Nick,msg.Params[0],"Nickname in use"))
					break
				}
				some := map[string]struct{}{}
				for _, v := range curcl.Channels {
					v.Nick(curcl, some, msg.Params[0])
				}
				SendToAllServersButOne(nil, M(curcl.Prefix(), "NICK", msg.Params[0]))
				curcl.Nick = msg.Params[0]
				if len(msg.Params) < 10 {
					quit = "Protocol violation"
					goto break2
				}
				}
				break
				CASE_NICK_SERVER:
        // NICK burnout 1 1527705211 burnout forever.nerdforlife.net piano.thelandorg.com 1527705211 +iowrxzt 192.168.0.1 RaTAkw== :burnout
        //  -1    0     1  2          3           4                         5               6           7         8       9        10
				newcl := &Client{ID: uniqid(), Nick: msg.Params[0], User: msg.Params[3], Host: msg.Params[4], TS: strconvOr(msg.Params[2], 0), ServerName: msg.Params[5],
						Real: msg.Params[10], TLS: strings.Contains(msg.Params[7], "z"), Oper: strings.Contains(msg.Params[7], "o"), Server: false, Remote: true,
						RawConn: cl.RawConn, Conn: cl.Conn, InCommand: make(chan *irc.Message, 32)}
				// Working with nick collisions
				oldcl := ClientByNick(newcl.Nick)
				if oldcl != nil && oldcl.TS > newcl.TS {
					oldcl.Quit("Nick collision (newer)")
				} else if oldcl != nil && oldcl.TS <= newcl.TS {
					newcl.Kill("Nick collision (older)")
					break
				}
				for k, v := range confdata.Ban {
					if glob.Glob(k, newcl.Nick + "!" + newcl.User + "@" + newcl.Host) {
						newcl.Kill("Banned: " + v.Reason)
						goto break3
					}
				}
				SendToAllServersButOne(cl, msg)
				clients.Set(newcl.ID, newcl)
				break3:
			break
			case "SQUIT":
			case "KILL":
				if len(msg.Params) < 1 {
					conn.Encode(NEED_PARAMS)
					break
				}
				km := "Killed"
				if !cl.Server && len(msg.Params) == 2 {
					km += ": " + msg.Params[1]
				} else if len(msg.Params) == 2 {
					km = msg.Params[1]
				}
				cl2 := ClientByNick(msg.Params[0])
				if cl2 == nil {
					conn.Encode(M(mypfx(), "401", msg.Params[0], "No such target"))
					break
				}
				cl2.Kill(km)
			break
			case "REHASH":
				if !cl.Oper { break }
				readconf()
			break
			case "OPER":
				if curcl.Remote {
					curcl.Oper = true
					SendToAllServersButOne(cl, M(curcl.Prefix(), "OPER"))
					break
				}
				if len(msg.Params) < 2 {
					conn.Encode(NEED_PARAMS)
					break
				}
				passh := fmt.Sprintf("%x", sha256.Sum256([]byte(msg.Params[1])))
				if blk, ok := confdata.Oper[msg.Params[0]]; (!ok || blk.Password != passh) {
					conn.Encode(M(mypfx(), "491", cl.Nick, "Bad password"))
					log.Println("OPER", "User " + cl.Nick + " failed authentication.")
					break
				}
				cl.Oper = true
				cl.SNO = "lcifwe"
				conn.Encode(M(mypfx(), "MODE", cl.Nick, "+o", cl.SNO))
				log.Println("OPER", "User " + cl.Nick + " is now an IRC operator")
				SendToAllServersButOne(cl, M(curcl.Prefix(), "OPER"))
			break
			case "CONNECT":
				if len(msg.Params) != 1 || !cl.Oper {
					conn.Encode(NEED_PARAMS)
					break
				}
				srv, ok := confdata.Link[msg.Params[0]]
				if !ok {
					conn.Encode(M(mypfx(), "NOTICE", cl.Nick, "Can't connect to server: not in configuration!"))
					break
				}
				go ConnectServer(msg.Params[0], srv.Address, srv.TLS)
			break
			case "PING":
				msg.Prefix = mypfx()
				msg.Command = "PONG"
				conn.Encode(msg)
			break
			case "WHO":
				i := 0
				if len(msg.Params) < 1 {
					conn.Encode(NEED_PARAMS)
					break
				}
				tgt := clients
				if msg.Params[0] != "0" {
					ch := FindChannel(msg.Params[0])
					if ch == nil {
						break
					}
					tgt = ch.Users
				}
				reqop := len(msg.Params) == 2 && strings.Contains(msg.Params[1], "o")
				reqlocal := len(msg.Params) == 2 && strings.Contains(msg.Params[1], "l")
				for t := range tgt.IterBuffered() {
					c2 := t.Val.(*Client)
					if reqop && !c2.Oper { continue }
					if c2.Remote && reqlocal { continue }
					if c2.Server { continue }
					if i > 250 { break }
					i++
					conn.Encode(M(mypfx(), "352", cl.Nick, msg.Params[0], c2.User, c2.Host, c2.ServerName, c2.Nick, "*", (map[bool]string{true:"0",false:"1"})[c2.Remote] + " " + c2.Real))
				}
				conn.Encode(M(mypfx(), "315", cl.Nick, msg.Params[0], "End of RPL_WHOREPLY"))
			break
			case "LINKS":
				conn.Encode(M(mypfx(), "364", cl.Nick, confdata.Server.Name, confdata.Server.Name, "0 " + confdata.Server.Description))
				for t := range clients.IterBuffered() {
					c2 := t.Val.(*Client)
					if !c2.Server { continue }
					hops := "1"
					if c2.Remote { hops = "2" }
					conn.Encode(M(mypfx(), "364", cl.Nick, c2.Nick, c2.ServerName, hops + " " + c2.Real))
				}
				conn.Encode(M(mypfx(), "365", cl.Nick, "*", "End of RPL_LINKS"))
			break
			case "MODE":
				if len(msg.Params) < 1 {
					conn.Encode(NEED_PARAMS)
					break
				}
				if strings.ToLower(msg.Params[0]) == strings.ToLower(cl.Nick) {
					if len(msg.Params) >= 2 && cl.Oper && msg.Params[1] == "+o" {
						if len(msg.Params) == 3 {
							cl.SNO = msg.Params[2]
							break
						}
						conn.Encode(M(mypfx(), "MODE", cl.Nick, "+o", cl.SNO))
					}
					break
				}
				ch := FindChannel(msg.Params[0])
				if ch == nil {
					conn.Encode(M(mypfx(), "401", msg.Params[0], "No such target"))
					break
				}
				if len(msg.Params) > 1 {
					ch.Mode(curcl, msg.Params[1:]...)
				} else {
					ch.Mode(curcl)
				}
			break
			case "KICK":
				mesg := "Kicked"
				if len(msg.Params) == 3 {
					mesg = msg.Params[1]
				}
				if len(msg.Params) < 2 {
					conn.Encode(NEED_PARAMS)
				}
				ch := FindChannel(msg.Params[0])
				if ch == nil {
					conn.Encode(M(mypfx(), "401", msg.Params[0], "No such target"))
					break
				}
				tgt := ClientByNick(msg.Params[1])
				if tgt == nil {
					conn.Encode(M(mypfx(), "401", msg.Params[1], "No such target"))
					break
				}
				ch.Kick(curcl, tgt, mesg)
				if ch.Users.Count() == 0 { channels.Remove(strings.ToLower(ch.Name)) }
			break
			case "PART":
				mesg := "Left"
				if len(msg.Params) == 2 {
					mesg = msg.Params[1]
				} else if len(msg.Params) != 1 {
					conn.Encode(NEED_PARAMS)
					break
				}
				if msg.Params[0][0] != '#' { break }
				x := FindTarget(msg.Params[0])
				if x == nil {
					conn.Encode(M(mypfx(), "401", msg.Params[0], "No such target"))
					break
				}
				ch := (interface{}(x)).(*Channel)
				_, ok := ch.Users.Get(curcl.ID)
				if ok { ch.Part(curcl, mesg) }
				if ch.Users.Count() == 0 { channels.Remove(strings.ToLower(ch.Name)) }
			break
			case "QUIT":
				if len(msg.Params) == 0 {
					msg.Params[0] = "Quit"
				}
				if curcl != cl {
					curcl.Quit(msg.Params[0])
					break
				}
				quit = msg.Params[0]
				goto break2
			break
			case "MOTD":
				conn.Encode(M(mypfx(), "375", curcl.Nick, "- Message of the day"))
				for _, v := range getmotd() {
					conn.Encode(M(mypfx(), "372", curcl.Nick, "- " + v))
				}
				conn.Encode(M(mypfx(), "376", curcl.Nick, "End of /MOTD reply"))
			break
			case "WHOIS":
				if len(msg.Params) < 1 {
					conn.Encode(NEED_PARAMS)
					break
				}
				sinfo := "Remote server"
				clnt := ClientByNick(msg.Params[0])
				if clnt == nil {
					conn.Encode(M(mypfx(), "401", msg.Params[0], "No such target"))
					break
				}
				if clnt.ServerName == confdata.Server.Name {
					sinfo = confdata.Server.Description
				}
				conn.Encode(M(mypfx(), "311", curcl.Nick, clnt.Nick, clnt.User, clnt.Host, "*", clnt.Real))
				chans := []string{}
				for _, v := range clnt.Channels {
					chans = append(chans, fmt.Sprintf("%c%s", v.MaxUserStatus(clnt), v.Name))
				}
				conn.Encode(M(mypfx(), "319", curcl.Nick, clnt.Nick, strings.Join(chans, " ")))
				if clnt.Oper {
					conn.Encode(M(mypfx(), "313", curcl.Nick, clnt.Nick, "is an IRC Operator"))
				}
				if clnt.TLS {
					conn.Encode(M(mypfx(), "320", curcl.Nick, clnt.Nick, "is using a secure connection"))
				}
				conn.Encode(M(mypfx(), "312", curcl.Nick, clnt.Nick, clnt.ServerName, sinfo))
				conn.Encode(M(mypfx(), "318", curcl.Nick, clnt.Nick, "End of RPL_WHOIS"))
			break
			case "NOTICE":
			case "PRIVMSG":
				if len(msg.Params) != 2 {
					conn.Encode(NEED_PARAMS)
					break
				}
				tgt := FindTarget(msg.Params[0])
				if tgt == nil {
					conn.Encode(M(mypfx(), "401", msg.Params[0], "No such target"))
					break
				}
				tgt.Message(curcl, msg.Command, msg.Params[1])
			break
			case "NAMES":
				if len(msg.Params) < 1 { break }
				if msg.Params[0][0] != '#' { break }
				x := FindTarget(msg.Params[0])
				if x == nil { break }
				c2 := (interface{}(x)).(*Channel)
				c2.SendNames(cl)
			break
			case "TOPIC":
				if len(msg.Params) < 1 { break }
				if len(msg.Params) == 4 {
					msg.Params = []string{msg.Params[0], msg.Params[3]}
				}
				if msg.Params[0][0] != '#' { break }
				x := FindTarget(msg.Params[0])
				if x == nil {
					conn.Encode(M(mypfx(), "401", msg.Params[0], "No such target"))
				break }
				c2 := (interface{}(x)).(*Channel)
				if len(msg.Params) == 1 {
					conn.Encode(M(mypfx(),"332",cl.Nick,c2.Name,c2.Topic))
				} else {
					c2.SetTopic(curcl, msg.Params[1])
				}
			break
			case "JOIN":
				if len(msg.Params) != 1 {
					break
				}
				for _, c := range strings.Split(msg.Params[0], ",") {
					if c == "" { continue }
					if c[0] != '#' { continue }
					isnew := false
					channel, ok := channels.Get(strings.ToLower(c))
					if !ok {
						isnew = true
						channel = NewChannel(c)
					}
					c2 := channel.(*Channel)
					err := c2.Join(curcl)
					if isnew && !cl.Server {
						c2.Status.Set(curcl.ID,[]byte{'q',0,'o',0,0})
						SendToAllServersButOne(nil, M(mypfx(),"MODE",c2.Name,"+qo",curcl.Nick,curcl.Nick,TS()))
					}
					if err != nil {
						conn.Encode(M(mypfx(),"474",cl.Nick,c,err.Error()))
						continue
					}
					if cl.Server { continue }
					conn.Encode(M(mypfx(),"332",cl.Nick,c2.Name,c2.Topic))
					c2.SendNames(cl)
					c2.Mode(cl)
				}
			default:
				if !cl.Server { conn.Encode(M(mypfx(),"421",cl.Nick,msg.Command,"Unknown command")) }
			break
		}
		_ = msg
	}
	break2:
	clients.Remove(cl.ID)
	if cl.ID != "" {
		cl.Quit(quit)
	}
	_ = quit
}
