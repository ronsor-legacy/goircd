package main

type ServerBlock struct {
	Name string
	Description string
	MOTD string
	Network string
}
type ListenBlock struct {
	Address string
	TLS bool
}
type TLSBlock struct {
	Key string
	Cert string
}
type OperBlock struct {
	Password string
	NeedTLS bool
	Class string
}
type LinkBlock struct {
	Address string
	TLS bool
	Auto bool
	Password string
}
type BanBlock struct {
	Reason string
	Remote bool
}
type SpoofBlock struct {
	Spoof string
}
type Config struct {
	Server ServerBlock
	Listen map[string]*ListenBlock
	TLS TLSBlock
	Oper map[string]*OperBlock
	Link map[string]*LinkBlock
	Ban map[string]*BanBlock
	Spoof map[string]*SpoofBlock
}
