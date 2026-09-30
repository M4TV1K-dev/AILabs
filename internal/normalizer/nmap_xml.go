package normalizer

import "encoding/xml"

// NmapRun represents the root XML structure from Nmap -oX output
type NmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Scanner string     `xml:"scanner,attr"`
	Args    string     `xml:"args,attr"`
	Start   string     `xml:"start,attr"`
	Version string     `xml:"version,attr"`
	Hosts   []NmapHost `xml:"host"`
}

// NmapHost represents a single scanned host
type NmapHost struct {
	Status    NmapStatus    `xml:"status"`
	Addresses []NmapAddress `xml:"address"`
	Hostnames NmapHostnames `xml:"hostnames"`
	Ports     NmapPorts     `xml:"ports"`
	OS        NmapOS        `xml:"os"`
}

// NmapStatus host status (up/down)
type NmapStatus struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

// NmapAddress ip/mac address
type NmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

// NmapHostnames list of hostnames
type NmapHostnames struct {
	Hostnames []NmapHostname `xml:"hostname"`
}

// NmapHostname hostname item
type NmapHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

// NmapPorts ports list
type NmapPorts struct {
	Ports []NmapPort `xml:"port"`
}

// NmapPort single port details
type NmapPort struct {
	Protocol string         `xml:"protocol,attr"`
	PortID   int            `xml:"portid,attr"`
	State    NmapPortState  `xml:"state"`
	Service  NmapService    `xml:"service"`
	Scripts  []NmapScript   `xml:"script"`
}

// NmapPortState port state (open/closed/filtered)
type NmapPortState struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

// NmapService service metadata and banners
type NmapService struct {
	Name      string `xml:"name,attr"`
	Product   string `xml:"product,attr"`
	Version   string `xml:"version,attr"`
	ExtraInfo string `xml:"extrainfo,attr"`
	OSType    string `xml:"ostype,attr"`
	Method    string `xml:"method,attr"`
	Conf      string `xml:"conf,attr"`
}

// NmapScript NSE script output
type NmapScript struct {
	ID     string      `xml:"id,attr"`
	Output string      `xml:"output,attr"`
	Tables []NmapTable `xml:"table"`
	Elems  []NmapElem  `xml:"elem"`
}

// NmapTable structured NSE table output
type NmapTable struct {
	Key    string      `xml:"key,attr"`
	Tables []NmapTable `xml:"table"`
	Elems  []NmapElem  `xml:"elem"`
}

// NmapElem key-value element in NSE script output
type NmapElem struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

// NmapOS OS detection results
type NmapOS struct {
	OSMatches []NmapOSMatch `xml:"osmatch"`
}

// NmapOSMatch matched OS fingerprint
type NmapOSMatch struct {
	Name     string `xml:"name,attr"`
	Accuracy string `xml:"accuracy,attr"`
}
