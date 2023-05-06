package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"time"
)

var Cfg *Config

func main() {
	conffile := flag.String("c", "revizorro.conf", "Configuration file")
	flag.Parse()
	Cfg, _ = ReadConfigFile(*conffile)

	_url := Cfg.GetString("APIURL", "https://proxy-01.eais-upload.451f.cc")
	_key := Cfg.GetString("APIKey", "****")
	_workdir := Cfg.GetString("workdir", "/tmp")
	_results := Cfg.GetString("results", "/tmp")

	_curdumpfile := fmt.Sprintf("%s/current", _workdir)
	_dumpfile := fmt.Sprintf("%s/dump.zip", _workdir)
	_xmldump := fmt.Sprintf("%s/dump.xml", _workdir)
	_domains := fmt.Sprintf("%s/domains.lst", _workdir)
	_mmdbfile := fmt.Sprintf("%s/GeoLite2-Country.mmdb", _workdir)

	_dnshost := Cfg.GetString("dnshost", "127.0.0.1")
	_dnsport := Cfg.GetString("dnsport", "53")

	_maxpool := Cfg.GetUint("maxpool", 100)
	_nextpool := Cfg.GetUint("nextpool", 80)
	_forcecount := Cfg.GetUint("forcecount", 0)

	for {
		dump, err := GetLastDumpId(_url, _key)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err.Error())
		}
		cur, err := ReadCurrentDumpId(_curdumpfile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err.Error())
			continue
		}
		if dump == nil {
			fmt.Fprint(os.Stderr, "Can't fetch the hot dump!\n")
		} else if dump.CRC != "" && dump.CRC != cur.CRC {
			fmt.Println("Get new file!")
			l := memTest()
			err := FetchDump(dump.Id, _dumpfile, _url, _key)
			if l != memTest() {
				fmt.Fprintf(os.Stderr, "Memory leak %s\n", "FetchDump")
			}
			if err == nil {
				l = memTest()
				err = DumpUnzip(_dumpfile, _xmldump)
				if l != memTest() {
					fmt.Fprintf(os.Stderr, "Memory leak %s\n", "DumpUnzip")
				}
				if err == nil {
					l = memTest()
					err = ParseDomains(_xmldump, _domains)
					if l != memTest() {
						fmt.Fprintf(os.Stderr, "Memory leak %s\n", "ParseDomains")
					}
					if err == nil {
						err = WriteCurrentDumpId(_curdumpfile, dump)
					} else {
						fmt.Fprintf(os.Stderr, "Error: %s\n", err.Error())
					}
				} else {
					fmt.Fprintf(os.Stderr, "Error: %s\n", err.Error())
				}
			} else {
				fmt.Fprintf(os.Stderr, "Error: %s\n", err.Error())
			}
		} else if dump.CRC != "" && dump.CRC == cur.CRC {
			fmt.Println("Not changed, but new dump metainfo")
			err = WriteCurrentDumpId(_curdumpfile, dump)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %s\n", err.Error())
			}
		} else {
			fmt.Fprint(os.Stderr, "Not changed!\n")
		}
		l := memTest()
		ig := runtime.NumGoroutine()
		err = ResolveList(_dnshost, _dnsport, _domains, _mmdbfile, _workdir, _results, _maxpool, _nextpool, _forcecount, cur)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err.Error())
			time.Sleep(10 * time.Second)
		} else {
			time.Sleep(10 * time.Second)
		}
		l1 := memTest()
		if l != l1 {
			fmt.Fprintf(os.Stderr, "Memory leak %d = %d %s\n", l, l1, "ResolveList")
		}
		ig1 := runtime.NumGoroutine()
		if ig != ig1 {
			fmt.Fprintf(os.Stderr, "Goroutines leak %d = %d\n", ig, ig1)
		}
	}
}
