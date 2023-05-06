package main

import (
	"archive/zip"
	"encoding/xml"
	"fmt"
	"golang.org/x/net/html/charset"
	"golang.org/x/net/idna"
	"io"
	"os"
	"regexp"
	"strings"
)

const (
	CXMLDumpName string = "dump.xml"
)

type TReg struct {
	UpdateTime         string
	UpdateTimeUrgently string
	FormatVersion      string
}

type TContent struct {
	Url                         []string `xml:"url"`
	IP                          []string `xml:"ip"`
	Subnet                      []string `xml:"ipSubnet"`
	Domain                      string   `xml:"domain"`
	Id                          string   `xml:"id,attr"`
	IncludeTime                 string   `xml:"includeTime,attr"`
	BlockType                   string   `xml:"blockType,attr"`
	UrgencyType                 bool     `xml:"urgencyType,attr"`
	IPv6, BogusDomain, BogusURL bool     `xml:"-"`
}

func DumpUnzip(src, filename string) error {
	tmpfile := fmt.Sprintf("%s-temp", filename)
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
		if f.Name != CXMLDumpName {
			continue
		}
		if f.FileInfo().IsDir() {
			return fmt.Errorf("File is dir")
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer rc.Close()
		f, err := os.Create(tmpfile)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(f, rc)
		if err != nil {
			return err
		}
	}
	err = os.Rename(tmpfile, filename)
	if err != nil {
		return err
	}
	return nil
}

func ParseDomains(src, dest string) error {
	_dest := fmt.Sprintf("%s-temp", dest)
	reg := TReg{}
	domains := make(map[string]bool)
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	re, _ := regexp.Compile(`^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$`)
	defer f.Close()
	decoder := xml.NewDecoder(f)
	decoder.CharsetReader = charset.NewReaderLabel
	for {
		t, err := decoder.Token()
		if t == nil {
			if err != io.EOF {
				return err
			}
			break
		}
		switch _e := t.(type) {
		case xml.StartElement:
			_name := _e.Name.Local
			switch _name {
			case "register":
				for _, _a := range _e.Attr {
					if _a.Name.Local == "formatVersion" {
						reg.FormatVersion = _a.Value
					} else if _a.Name.Local == "updateTime" {
						reg.UpdateTime = _a.Value
					} else if _a.Name.Local == "updateTimeUrgently" {
						reg.UpdateTimeUrgently = _a.Value
					}
				}
			case "content":
				var v TContent
				err := decoder.DecodeElement(&v, &_e)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Decode Error: %s\n", err.Error())
					continue
				}
				if v.Domain == "" {
					continue
				}
				v.Domain = strings.ToLower(v.Domain)
				v.Domain = strings.Replace(v.Domain, ",", ".", -1)
				v.Domain = strings.Replace(v.Domain, " ", "", -1)
				// IPv4
				if re.MatchString(v.Domain) {
					continue
				}
				domain, err := idna.ToASCII(v.Domain)
				if err != nil {
					fmt.Fprintf(os.Stderr, "IDNA parse error: %s\n", err.Error())
					continue
				}
				domain = strings.TrimPrefix(domain, "*.")
				// domain syntax
				if !isDomainName(domain) {
					fmt.Fprintf(os.Stderr, "Not valid domain name: %s\n", v.Domain)
					continue
				}
				domains[domain] = true
			}
		default:
			//fmt.Printf("%v\n", _e)
		}
	}
	dl, err := os.Create(_dest)
	if err != nil {
		return err
	}
	defer dl.Close()
	for k, _ := range domains {
		_, err = dl.WriteString(k)
		if err != nil {
			return err
		}
		_, err = dl.WriteString("\n")
		if err != nil {
			return err
		}
	}
	err = os.Rename(_dest, dest)
	if err != nil {
		return err
	}
	return nil
}
