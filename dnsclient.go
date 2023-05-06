package main

import (
	"fmt"
	"github.com/miekg/dns"
	"math/rand"
	"time"
)

const ATTEMPTS = 1
const TIMEOUT = 30

func GetRR(domain string, nameservers []string, qtype uint16) (r *dns.Msg, rtt time.Duration, err error) {
	if len(nameservers) == 0 {
		err = fmt.Errorf("%s", "No nameservers!")
		return
	}
	for a := 0; a < ATTEMPTS; a++ {
		if a > 1 {
			time.Sleep(250 * time.Millisecond)
		}
		l := rand.Perm(len(nameservers))
		for _, i := range l {
			nameserver := nameservers[i]
			m := &dns.Msg{
				MsgHdr: dns.MsgHdr{
					//Authoritative: true,
					AuthenticatedData: true,
					CheckingDisabled:  true,
					RecursionDesired:  true,
					Opcode:            dns.OpcodeQuery,
					Rcode:             dns.RcodeSuccess,
				},
				Question: make([]dns.Question, 1),
			}
			o := &dns.OPT{
				Hdr: dns.RR_Header{
					Name:   ".",
					Rrtype: dns.TypeOPT,
				},
			}
			o.SetDo()
			o.SetUDPSize(dns.DefaultMsgSize)
			m.Extra = append(m.Extra, o)
			qt := qtype
			qc := uint16(dns.ClassINET)
			m.Question[0] = dns.Question{Name: dns.Fqdn(domain), Qtype: qt, Qclass: qc}
			m.Id = dns.Id()
			r, rtt, err = lookup(m, nameserver, true)
			if err == nil {
				break
			}
		}
		if err == nil {
			break
		}
	}
	return r, rtt, err
}

func lookup(m *dns.Msg, nameserver string, fallback bool) (r *dns.Msg, rtt time.Duration, err error) {
	c := new(dns.Client)
	c.Timeout = time.Second * TIMEOUT
	if fallback {
		c.Net = "udp"
	} else {
		c.Net = "tcp"
	}
	r, rtt, err = c.Exchange(m, nameserver)
	/*
		switch err {
		case nil:
			//do nothing
			                case dns.ErrTruncated:
						if fallback {
							// First EDNS, then TCP
							c.Net = "tcp"
							r, rtt, err = lookup(m, nameserver, false)
						}
		default:
			//do nothing
		}
	*/
	if r != nil {
		if r.Truncated {
			if fallback {
				// First EDNS, then TCP
				c.Net = "tcp"
				r, rtt, err = lookup(m, nameserver, false)
			}
		}
	}
	if err == nil {
		if r.Id != m.Id {
			err = fmt.Errorf("%s", "Id mismatch")
		}
		//fmt.Printf("%v", r)
		//fmt.Printf("\n;; query time: %.3d µs, server: %s(%s), size: %d bytes\n", rtt/1e3, nameserver, c.Net, r.Len())
	}
	if err != nil && r != nil {
		if m.Response || m.Opcode == dns.OpcodeQuery {
			err = nil
		}
	}
	return r, rtt, err
}
