package main

import (
	"gopkg.in/sorcix/irc.v2"
	"github.com/orcaman/concurrent-map"
	"time"
	"strings"
	"fmt"
	"github.com/ryanuber/go-glob"
)
var PREFIXMODE = map[byte]byte{
	'~':'q',
	'&':'a',
	'@':'o',
	'%':'h',
	'+':'v',
}
var MODEPREFIX = map[byte]byte{
	'q':'~',
	'a':'&',
	'o':'@',
	'h':'%',
	'v':'+',
}
var MODERANK = "+%@&~"
var STATPOS = "qaohv"
func GetRank(m byte) int {
	x := string(MODEPREFIX[m])+string(PREFIXMODE[m])+string(m)
	return strings.IndexAny(MODERANK, x)
}
var channels = cmap.New()
type Channel struct {
	Name string
	Topic string
	TS int64
	Users cmap.ConcurrentMap
	Status cmap.ConcurrentMap
	Bans []string
	Excepts []string
	ModeFlags string
}
func NewChannel(n string) *Channel {
	c := &Channel{Name:n,TS:time.Now().Unix(),Users:cmap.New(),Status:cmap.New(),ModeFlags:"",Topic:"(no topic set)"}
	channels.Set(strings.ToLower(n), c)
	return c
}
func (c *Channel) IsBanned(cl *Client) bool {
	hm := cl.Nick + "!" + cl.User + "@" + cl.Host
	for _, v := range c.Excepts {
		if glob.Glob(v, hm) {
			return false
		}
	}
	if !cl.Oper && c.HasFlag('O') { return false }
	for _, v := range c.Bans {
		if glob.Glob(v, hm) {
			return true
		}
	}
	return false
}
func (c *Channel) GetUserStatus(cl *Client) []byte {
	x, o := c.Status.Get(cl.ID)
	if !o { return []byte{0,0,0,0,0} }
	return x.([]byte)
}
func (c *Channel) HasUserStatus(cl *Client, stat byte) bool {
	return strings.Contains(string(c.GetUserStatus(cl)),string(stat))
}
func (c *Channel) MaxUserStatus(cl *Client) (r byte) {
	x := c.GetUserStatus(cl)
	r = ' '
	cx := strings.Replace(string(x), "\x00", "", -1)
	if len(cx) > 0 { r = MODEPREFIX[cx[0]] }
	return
}
func (c *Channel) SetUserStatus(cl *Client, set bool, stat byte) {
	ostat := stat
	if !set {
		stat = 0x00
	}
	x := c.GetUserStatus(cl)
	x[strings.IndexByte(STATPOS, ostat)] = stat
}
func (c *Channel) Mode(cl *Client, args ...string) {
	if len(args) == 0 {
		cl.Conn.Encode(M(mypfx(), "324", cl.Nick, c.Name, "+" + c.ModeFlags))
		return
	}
	stat := byte('+')
	ostat := byte(' ')
	apos := 1
	outstr := []string{""}
	for _, v2 := range args[0] {
		v := byte(v2)
		if v == '+' || v == '-' {
			stat = v
			continue
		}
		if strings.IndexByte("qaohv", v) != -1 {
			//fmt.Println(GetRank('q'),GetRank('~'))
			hasperm := cl.Server || cl.Remote || GetRank(c.MaxUserStatus(cl)) >= GetRank(v)
			if apos >= len(args) { continue }
			if !hasperm {
				cl.Conn.Encode(M(mypfx(), "482", cl.Nick, c.Name, fmt.Sprintf("Not allowed to set mode '%c'", v)))
				continue
			}
			clt := ClientByNick(args[apos])
			apos++
			if clt == nil { continue }
			if _, ok := c.Users.Get(clt.ID); !ok { continue }
			if stat == '+' {
				if ostat != stat {
					ostat = stat
					outstr[0] += string(stat)
				}
				outstr[0] += string(v)
				c.SetUserStatus(clt, true, v)
				outstr = append(outstr, clt.Nick)
			} else {
				if ostat != stat {
					ostat = stat
					outstr[0] += string(stat)
				}
				c.SetUserStatus(clt, false, v)
				outstr[0] += string(v)
				outstr = append(outstr, clt.Nick)
			}
			_ = hasperm
			continue
		}
		mys := c.MaxUserStatus(cl)
		if GetRank(mys) <= 0 {
			cl.Conn.Encode(M(mypfx(), "482", cl.Nick, c.Name, fmt.Sprintf("Not allowed to set mode '%c'", v)))
			continue
		}
		if strings.Contains("ntmsiO", string(v)) {
			if stat == '-' {
				c.UnsetFlag(v)
			} else {
				c.SetFlag(v)
			}
			if ostat != stat {
				ostat = stat
				outstr[0] += string(stat)
			}
			outstr[0] += string(v)
		}
		if v == 'b' {
			if apos >= len(args) {
				for k, b := range c.Bans {
					cl.Conn.Encode(M(mypfx(), "367", cl.Nick, c.Name, b, fmt.Sprintf("%d",k)))
				}
				cl.Conn.Encode(M(mypfx(), "368", cl.Nick, c.Name, "End of ban list"))
				continue
			}
			bn := args[apos]
			apos++
			if stat == '-' {
				i := 0
				for _, b := range c.Bans {
					if strings.ToLower(b) == strings.ToLower(bn) { continue }
					c.Bans[i] = b
					i++
				}
				if ostat != stat {
					ostat = stat
					outstr[0] += string(stat)
				}
				outstr[0] += "b"
				outstr = append(outstr, bn)
			} else {
				if ostat != stat {
					ostat = stat
					outstr[0] += string(stat)
				}
				outstr[0] += "b"
				outstr = append(outstr, bn)
				c.Bans = append(c.Bans, bn)
			}
			continue
		}
		if v == 'e' {
			if apos >= len(args) {
				for k, b := range c.Excepts {
					cl.Conn.Encode(M(mypfx(), "367", cl.Nick, c.Name, b, fmt.Sprintf("%d",k)))
				}
				cl.Conn.Encode(M(mypfx(), "368", cl.Nick, c.Name, "End of ban exception list"))
				continue
			}
			bn := args[apos]
			apos++
			if stat == '-' {
				i := 0
				for _, b := range c.Excepts {
					if strings.ToLower(b) == strings.ToLower(bn) { continue }
					c.Excepts[i] = b
					i++
				}
				if ostat != stat {
					ostat = stat
					outstr[0] += string(stat)
				}
				outstr[0] += "e"
				outstr = append(outstr, bn)
			} else {
				if ostat != stat {
					ostat = stat
					outstr[0] += string(stat)
				}
				outstr[0] += "e"
				outstr = append(outstr, bn)
				c.Excepts = append(c.Excepts, bn)
			}
			continue
		}
	}
	if len(outstr[0]) == 0 { return }
	full := append([]string{c.Name}, outstr...)
	cl2 := cl
	if !cl2.Server && !cl2.Remote { cl2 = nil }
	c.SendToAllButOne(cl2, M(cl.Prefix(), "MODE", full...))
	SendToAllServersButOne(cl2, M(cl.Prefix(), "MODE", full...))
}
func (c *Channel) HasFlag(f byte) bool {
	return strings.Contains(c.ModeFlags, string(f))
}
func (c *Channel) SetFlag(f byte) {
	if !c.HasFlag(f) {
		c.ModeFlags += string(f)
	}
}
func (c *Channel) UnsetFlag(f byte) {
	c.ModeFlags = strings.Replace(c.ModeFlags, string(f), "", -1)
}
func (c *Channel) SendNames(cl *Client) {
	out := []string{}
	for t := range c.Users.IterBuffered() {
		c2 := t.Val.(*Client)
		st := ""
		if c.MaxUserStatus(c2) != ' ' {
			st = string(c.MaxUserStatus(c2))
		}
		out = append(out, st+c2.Nick)
		if len(out) > 9 {
			cl.Conn.Encode(M(mypfx(),"353",cl.Nick,"=",c.Name,strings.Join(out," ")))
			out = []string{}
		}
	}
	if len(out) > 0 {
		cl.Conn.Encode(M(mypfx(),"353",cl.Nick,"=",c.Name,strings.Join(out," ")+" "))
	}
	cl.Conn.Encode(M(mypfx(),"366",cl.Nick,c.Name,"End of NAMES list"))
}
func (c *Channel) SetTopic(cl *Client, m string) {
	c.Topic = m
	cx := cl
	if !cl.Remote { cx = nil }
	if !cl.Server && !cl.Remote && GetRank(c.MaxUserStatus(cl)) <= 0 && c.HasFlag('t') {
		cl.Conn.Encode(M(mypfx(), "482", cl.Nick, c.Name, "Can't set topic (+t)"))
		return
	}
	c.SendToAllButOne(cx, M(cl.Prefix(),"TOPIC",c.Name,m))
	SendToAllServersButOne(cl, M(cl.Prefix(), "TOPIC", c.Name,m))
}
func (c *Channel) Message(cl *Client, t string, m string) {
	if c.HasFlag('n') && !c.Users.Has(cl.ID) {
		cl.Conn.Encode(M(mypfx(), "442", cl.Nick, c.Name, "Can't send (+n)"))
		return
	}
	if c.HasFlag('m') && GetRank(c.MaxUserStatus(cl)) < 0 {
		cl.Conn.Encode(M(mypfx(), "404", cl.Nick, c.Name, "Can't send (+m)"))
		return
	}
	c.SendToAllButOne(cl, M(cl.Prefix(), t, c.Name, m))
}
func (c *Channel) Join(cl *Client) error {
	if _, ok := c.Users.Get(cl.ID); ok {
		return nil
	}
	if !cl.Remote && c.IsBanned(cl) {
		return fmt.Errorf("You're banned (+b)")
	}
	c.Users.Set(cl.ID, cl)
	c.Status.Set(cl.ID, []byte{0,0,0,0,0})
	cl.Channels = append(cl.Channels, c)
	cx := (*Client)(nil)
	if cl.Remote {
		cx = cl
	}
	c.SendToAllButOne(cx, M(cl.Prefix(), "JOIN", c.Name))
	SendToAllServersButOne(cl, M(cl.Prefix(), "JOIN", c.Name))
	return nil
}
func (c *Channel) Kick(cl *Client, tgt *Client, msg string) {
	cx := cl
	if !cl.Remote {
		cx = nil
	}
	if _, ok := c.Users.Get(tgt.ID); !ok { return }
	if !cl.Remote && GetRank(c.MaxUserStatus(cl)) <= 0 {
		cl.Conn.Encode(M(mypfx(), "482", cl.Nick, c.Name, "You're not a channel operator"))
		return
	}
	c.SendToAllButOne(cx, M(cl.Prefix(), "KICK", c.Name, tgt.Nick, msg))
	SendToAllServersButOne(cl, M(cl.Prefix(), "KICK", c.Name, tgt.Nick, msg))
	c.Part(tgt, "")
}
func (c *Channel) Part(cl *Client, msg string) error {
	if msg != "" {
		c.SendToAllButOne(nil, M(cl.Prefix(), "PART", c.Name, msg))
		SendToAllServersButOne(cl, M(cl.Prefix(), "PART", c.Name, msg))
	}
	c.Users.Remove(cl.ID)
	c.Status.Remove(cl.ID)
	i := 0
	for _, v := range cl.Channels {
		if v == c { continue }
		cl.Channels[i] = v
		i++
	}
	cl.Channels = cl.Channels[:i]
	return nil
}
func (c *Channel) Nick(cl *Client, some map[string]struct{}, newn string) {
	c.SendToAllButSome(some, M(cl.Prefix(), "NICK", newn))
}
func (c *Channel) Quit(cl *Client, some map[string]struct{}, msg string) error {
	c.SendToAllButSome(some, M(cl.Prefix(), "QUIT", msg))
	c.Users.Remove(cl.ID)
	return nil
}
func (c *Channel) SendToAllButOne(cl *Client, m *irc.Message) {
	some := map[string]struct{}{}
	for t := range c.Users.IterBuffered() {
		c2 := t.Val.(*Client)
		if cl != nil && (c2.Conn == cl.Conn || c2.ID == cl.ID) {
			continue
		}
		if m.Command != "PRIVMSG" && m.Command != "NOTICE" && c2.Remote {
			continue
		}
		if _, ok := some[fmt.Sprintf("%v",c2.Conn)]; ok {
			continue
		}
		some[fmt.Sprintf("%v",c2.Conn)] = struct{}{}
		c2.Conn.Encode(m)
	}
}
func (c *Channel) SendToAllButSome(some map[string]struct{}, m *irc.Message) {
	for t := range c.Users.IterBuffered() {
		if _, ok := some[t.Key]; ok {
			continue
		}
		c := t.Val.(*Client)
		if c.Remote { continue }
		some[t.Key] = struct{}{}
		c.Conn.Encode(m)
	}
}
