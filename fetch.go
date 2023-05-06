package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

type TDumpAnswer struct {
	ArchStatus          int    `json:"a"`
	ArchSize            int    `json:"as"`
	CRC                 string `json:"crc"`
	CacheExpirationTime int    `json:"ct"`
	Id                  string `json:"id"`
	Size                int    `json:"s"`
	DbUpdateTime        int    `json:"u"`
	UpdateTime          int    `json:"ut"`
	UrgentUpdateTime    int    `json:"utu"`
}

func GetLastDumpId(url, key string) (*TDumpAnswer, error) {
	var dump *TDumpAnswer
	answer := make([]TDumpAnswer, 0)
	client := &http.Client{}
	_url := fmt.Sprintf("%s/last", url)
	_auth := fmt.Sprintf("Bearer %s", key)
	_time := fmt.Sprintf("%d", time.Now().Unix())
	req, err := http.NewRequest("GET", _url, nil)
	if err != nil {
		return dump, err
	}
	q := req.URL.Query()
	q.Add("ts", _time)
	req.URL.RawQuery = q.Encode()
	req.Header.Set("Authorization", _auth)
	resp, err := client.Do(req)
	if err != nil {
		return dump, err
	}
	if resp.StatusCode != 200 {
		return dump, fmt.Errorf("Not 200 HTTP code")
	}
	err = json.NewDecoder(resp.Body).Decode(&answer)
	if err != nil {
		return dump, err
	}
	if len(answer) == 0 {
		return dump, fmt.Errorf("Zero result")
	}
	dump = &answer[0]
	return dump, nil
}

func FetchDump(id, filename, url, key string) error {
	client := &http.Client{}
	_url := fmt.Sprintf("%s/get/%s", url, id)
	_tmpfilename := fmt.Sprintf("%s-tmp", filename)
	_auth := fmt.Sprintf("Bearer %s", key)
	out, err := os.Create(_tmpfilename)
	if err != nil {
		return err
	}
	defer out.Close()
	req, err := http.NewRequest("GET", _url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", _auth)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("Not 200 HTTP code")
	}
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}
	err = os.Rename(_tmpfilename, filename)
	if err != nil {
		return err
	}
	return nil
}

func ReadCurrentDumpId(filename string) (*TDumpAnswer, error) {
	result := TDumpAnswer{}
	if _, err := os.Stat(filename); err == nil {
		dat, err := ioutil.ReadFile(filename)
		if err != nil {
			return &result, err
		}
		err = json.Unmarshal(dat, &result)
		if err != nil {
			return &result, err
		}
	}
	return &result, nil
}

func WriteCurrentDumpId(filename string, dump *TDumpAnswer) error {
	dat, err := json.Marshal(dump)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filename, dat, 0644)
	if err != nil {
		return err
	}
	return nil
}
