package main

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"github.com/miekg/dns"
	"github.com/oschwald/maxminddb-golang"
	"golang.org/x/net/idna"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

const _DEFAULT_VERSION_ = "1.0"

func domainListRead(filename string) ([]string, int, error) {
	var domains []string
	c := 0
	re, _ := regexp.Compile(`^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$`)
	if file, err := os.Open(filename); err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			//if c >= 100 {
			//	continue
			//}
			_domain := scanner.Text()
			_domain = strings.ToLower(_domain)
			_domain = strings.TrimSuffix(_domain, ".")
			_domain = strings.Replace(_domain, ",", ".", -1)
			_domain = strings.Replace(_domain, " ", "", -1)
			if re.MatchString(_domain) {
				continue // IPv4
			}
			_domain, err = idna.ToASCII(_domain)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: IDNA parse error: %s\n", err.Error())
				continue
			}
			_domain = strings.TrimPrefix(_domain, "*.")
			if _domain == "" {
				continue
			}
			if !isDomainName(_domain) {
				fmt.Fprintf(os.Stderr, "Error: Not valid domain name: %s\n", _domain)
				continue
			}
			domains = append(domains, _domain)
			c++
		}
		if err := scanner.Err(); err != nil {
			return nil, c, err
		}
	} else {
		return nil, c, err
	}
	return domains, c, nil
}

type TGeoRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
} // Or any appropriate struct

type TDomainInfo struct {
	Domain  string       `json:"d"`
	Dnssec  bool         `json:"ad,omitempty"`
	Rrsig   bool         `json:"rs,omitempty"`
	Cname   *TDomainInfo `json:"cn,omitempty"`
	Ip4     []string     `json:"ip4,omitempty"`
	Ip6     []string     `json:"ip6,omitempty"`
	Rcode   string       `json:"rc,omitempty"`
	Ip6only bool         `json:"ip6o,omitempty"`
	Empty   bool         `json:"e,omitempty"`
	Error   bool         `json:"err,omitempty"`
	Country []string     `json:"c,omitempty"`
	Cn      bool         `json:"-"`
}

type TResolveStat struct {
	Domains  uint  `json:"domains"`
	Dnssec   uint  `json:"dnssec"`
	Rrsig    uint  `json:"rrsig"`
	Cname    uint  `json:"cname"`
	Fail     uint  `json:"servfail"`
	Nx       uint  `json:"nxdomain"`
	Ip4      uint  `json:"ip4"`
	Ip6      uint  `json:"ip6"`
	Uip4     uint  `json:"uniq_ip4"`
	Uip6     uint  `json:"uniq_ip6"`
	Ip6only  uint  `json:"ip6only"`
	Empty    uint  `json:"empty"`
	Errors   uint  `json:"errors"`
	Duration int64 `json:"duration"`
	Runet    uint  `json:"runet"`
}

func NewDomainInfo(domain string) *TDomainInfo {
	di := TDomainInfo{}
	di.Domain = domain
	di.Ip4 = make([]string, 0)
	di.Ip6 = make([]string, 0)
	di.Country = make([]string, 0)
	return &di
}

func PutRes(dinfo *TDomainInfo, w io.Writer, stat *TResolveStat, mmdb *maxminddb.Reader, Uip4, Uip6 map[string]string) {
	var ip net.IP
	var r TGeoRecord
	var fl bool
	var err error
	flru := false
	if dinfo.Error {
		stat.Errors++
	} else {
		if dinfo.Cn {
			stat.Cname++
		}
		if len(dinfo.Ip4) > 0 {
			stat.Ip4++
			for _, i := range dinfo.Ip4 {
				if mmdb != nil {
					ip = net.ParseIP(i)
					err = mmdb.Lookup(ip, &r)
					if err != nil {
						Uip4[i] = " "
					} else {
						Uip4[i] = r.Country.ISOCode
						fl = true
						for _, _v := range dinfo.Country {
							if _v == r.Country.ISOCode {
								fl = false
								break
							}
						}
						if fl {
							if r.Country.ISOCode == "RU" {
								flru = true
							}
							dinfo.Country = append(dinfo.Country, r.Country.ISOCode)
						}
					}
				} else {
					Uip4[i] = " "
				}
			}
			stat.Uip4 = uint(len(Uip4))
		}
		if len(dinfo.Ip6) > 0 {
			stat.Ip6++
			for _, i := range dinfo.Ip6 {
				if mmdb != nil {
					ip = net.ParseIP(i)
					err = mmdb.Lookup(ip, &r)
					if err != nil {
						Uip6[i] = " "
					} else {
						Uip6[i] = r.Country.ISOCode
						fl = true
						for _, _v := range dinfo.Country {
							if _v == r.Country.ISOCode {
								fl = false
								break
							}
						}
						if fl {
							if r.Country.ISOCode == "RU" {
								flru = true
							}
							dinfo.Country = append(dinfo.Country, r.Country.ISOCode)
						}
					}
				} else {
					Uip6[i] = " "
				}
			}
			stat.Uip6 = uint(len(Uip6))
		}
		if flru {
			stat.Runet++
		}
		if dinfo.Dnssec {
			stat.Dnssec++
		}
		if dinfo.Rrsig {
			stat.Rrsig++
		}
		if dinfo.Rcode == dns.RcodeToString[dns.RcodeNameError] {
			stat.Nx++
		}
		if dinfo.Rcode == dns.RcodeToString[dns.RcodeServerFailure] {
			stat.Fail++
		} else {
			if dinfo.Ip6only {
				stat.Ip6only++
			}
			if dinfo.Empty {
				stat.Empty++
			}
		}
	}
	res, err := json.MarshalIndent(dinfo, "\t", "\t")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Can't marshal json: %s", err.Error())
	}
	fmt.Fprint(w, string(res))
}

func ResolveList(dnshost, dnsport, domainsfile, mmdbfile, workdir, results string, maxpool, nextpool, forcecount uint, header *TDumpAnswer) error {
	var domains []string
	var Uip4 = make(map[string]string)
	var Uip6 = make(map[string]string)
	stat := &TResolveStat{}
	_now := time.Now().Unix()
	_time := fmt.Sprintf("%d", _now)
	nameservers := []string{dnshost}
	for j, nameserver := range nameservers {
		if i := net.ParseIP(nameserver); i != nil {
			nameservers[j] = net.JoinHostPort(nameserver, dnsport)
		} else {
			nameservers[j] = dns.Fqdn(nameserver) + ":" + dnsport
		}
	}
	domains, _, err := domainListRead(domainsfile)
	if err != nil {
		return err
	}
	resultfile := fmt.Sprintf("%s/result.json", workdir)
	tmpfile := fmt.Sprintf("%s/result.json.tmp", workdir)
	if file, err := os.Create(tmpfile); err == nil {
		defer file.Close()
		geodb, err := maxminddb.Open(mmdbfile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Internal error, can't open MaxMindDB: %s\n", err.Error())
		} else {
			defer geodb.Close()
		}
		w := bufio.NewWriter(file)
		messages := make(chan *TDomainInfo, maxpool)
		var cnt, allcnt uint
		var wg sync.WaitGroup
		_h, err := json.MarshalIndent(header, "\t", "\t")
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "{\n\t\"v\": \"%s\",\n\t\"t\": %s,\n\t\"h\": %s,\n\t\"list\": [\n", _DEFAULT_VERSION_, _time, _h)
		for _, domain := range domains {
			if forcecount > 0 && stat.Domains >= forcecount {
				break
			}
			cnt++
			stat.Domains++
			wg.Add(1)
			go func(_domain string) {
				cnames := make(map[string]string)
				dinfo := NewDomainInfo(_domain)
				_ip4 := 0
				_ip6 := 0
				defer wg.Done()
				if r, _, err := GetRR(_domain, nameservers, dns.TypeA); err == nil {
					dinfo.Dnssec = r.AuthenticatedData
					switch r.Rcode {
					case dns.RcodeSuccess:
						if len(r.Answer) > 0 {
							if len(r.Answer) > 99 {
								fmt.Fprintf(os.Stderr, "Internal error, for %s, Answer too big: %d\n", _domain, len(r.Answer))
							}
							for _, rr := range r.Answer {
								if rr.Header().Rrtype == dns.TypeA {
									dinfo.Ip4 = append(dinfo.Ip4, rr.(*dns.A).A.String())
								} else if rr.Header().Rrtype == dns.TypeCNAME {
									cnames[strings.TrimSuffix(rr.Header().Name, ".")] = strings.TrimSuffix(rr.(*dns.CNAME).Target, ".")
								} else if rr.Header().Rrtype == dns.TypeRRSIG {
									//fmt.Fprintf(os.Stderr, "Warning: RRSIG (%s): %#v", _domain, r.MsgHdr)
									dinfo.Rrsig = true
								} else {
									fmt.Fprintf(os.Stderr, "Warning: unknown answer (%s): %s\n", _domain, rr.String())
								}
								_ip4++
							}
						}
					default:
						dinfo.Rcode = dns.RcodeToString[r.Rcode]
					}
				} else {
					// dinfo.Rcode = dns.RcodeToString[dns.RcodeServerFailure]
					dinfo.Error = true
					fmt.Fprintf(os.Stderr, "Type A. Internal error (%s): %s\n", _domain, err.Error())
				}
				if r, _, err := GetRR(_domain, nameservers, dns.TypeAAAA); err == nil {
					dinfo.Dnssec = r.AuthenticatedData
					switch r.Rcode {
					case dns.RcodeSuccess:
						if len(r.Answer) > 0 {
							if len(r.Answer) > 99 {
								fmt.Fprintf(os.Stderr, "Internal error, for %s, Answer too big: %d\n", _domain, len(r.Answer))
							}
							for _, rr := range r.Answer {
								if rr.Header().Rrtype == dns.TypeAAAA {
									dinfo.Ip6 = append(dinfo.Ip6, rr.(*dns.AAAA).AAAA.String())
								} else if rr.Header().Rrtype == dns.TypeCNAME {
									cnames[strings.TrimSuffix(rr.Header().Name, ".")] = strings.TrimSuffix(rr.(*dns.CNAME).Target, ".")
								} else if rr.Header().Rrtype == dns.TypeRRSIG {
									dinfo.Rrsig = true
									// fmt.Fprintf(os.Stderr, "Warning: RRSIG (%s): %#v", _domain, r.MsgHdr)
								} else {
									fmt.Fprintf(os.Stderr, "Warning: unknown answer (%s): %s\n", _domain, rr.String())
								}
								_ip6++
							}
						}
					default:
						dinfo.Rcode = dns.RcodeToString[r.Rcode]
					}
				} else {
					// dinfo.Rcode = dns.RcodeToString[dns.RcodeServerFailure]
					dinfo.Error = true
					fmt.Fprintf(os.Stderr, "Type AAAA. Internal error (%s): %s\n", _domain, err.Error())
				}
				if _ip4+_ip6 == 0 && !dinfo.Error && dinfo.Rcode == "" {
					dinfo.Empty = true
				}
				if _ip6 > 0 && _ip4 == 0 {
					dinfo.Ip6only = true
				}
				if len(cnames) > 0 {
					dinfo.Cn = true
					_cn := _domain
					_cdi := dinfo
					cname_i := 0
					for {
						if v, ok := cnames[_cn]; ok {
							_ndi := NewDomainInfo(_cn)
							_cn = v
							_cdi.Cname = _ndi
							_cdi = _ndi
						} else {
							_ndi := NewDomainInfo(_cn)
							_cdi.Cname = _ndi
							break
						}
						cname_i++
						if cname_i == 10 {
							fmt.Fprintf(os.Stderr, "Internal error for %s, CNAME ERROR: %#v\n", _domain, cnames)
							break
						}
					}
				}
				//fmt.Println(string(res))
				messages <- dinfo
			}(domain)
			if cnt >= maxpool {
				for cnt >= nextpool {
					select {
					case res := <-messages:
						cnt--
						allcnt++
						PutRes(res, w, stat, geodb, Uip4, Uip6)
						if cnt >= 1 {
							fmt.Fprint(w, ",\n")
						} else {
							fmt.Fprint(w, "\n")
						}
					}
				}
			}
		}
		for cnt > 0 {
			select {
			case res := <-messages:
				cnt--
				allcnt++
				PutRes(res, w, stat, geodb, Uip4, Uip6)
				if cnt >= 1 {
					fmt.Fprint(w, ",\n")
				} else {
					fmt.Fprint(w, "\n")
				}
			}
		}
		wg.Wait()
		close(messages)
		stat.Duration = time.Now().Unix() - _now
		_f, _ := json.MarshalIndent(stat, "\t", "\t")
		fmt.Fprintf(w, "\t],\n\t\"stat\": %s\n}\n", _f)
		w.Flush()
		// fmt.Printf("C: %d\n\n", cnt)
	} else {
		return err
	}
	// fmt.Printf("Domains: %d\n", stat_cnt_domains)
	os.Rename(tmpfile, resultfile)

	seqfile := fmt.Sprintf("%s/%s.gz", results, _time)
	tmpseqfile := seqfile + ".tmp"
	if in, err := os.Open(resultfile); err == nil {
		defer in.Close()
		if out, err := os.Create(tmpseqfile); err == nil {
			defer out.Close()
			zw := gzip.NewWriter(out)
			defer zw.Close()
			if _, err = io.Copy(zw, in); err != nil {
				return err
			}
			err = zw.Flush()
			if err != nil {
				return err
			}
			err = out.Sync()
			if err != nil {
				return err
			}
		} else {
			return err
		}
	} else {
		return err
	}
	os.Rename(tmpseqfile, seqfile)
	return nil
}
