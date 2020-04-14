package main

import (
	"flag"
	"fmt"
	"github.com/theFido/fdexplorer/pkg/fdexplorer"
	"io/ioutil"
	"net/http"
	"sync"
	"time"
)

type pinger struct {
	remoteUrl    string
	client       http.Client
	errorCount   int
	successCount int
	mu           sync.Mutex
}

func (p *pinger) run(workers int) {
	var wg sync.WaitGroup
	wg.Add(1)
	for i := 0; i < workers; i++ {
		go func() {
			for {
				req, _ := http.NewRequest("GET", p.remoteUrl, nil)
				resp, err := p.client.Do(req)
				if err != nil {
					p.mu.Lock()
					p.errorCount++
					p.mu.Unlock()
					fmt.Println(err)
					continue
				}
				ioutil.ReadAll(resp.Body)
				resp.Body.Close()
				p.mu.Lock()
				p.successCount++
				p.mu.Unlock()
			}
		}()
	}
	go func() {
		for {
			p.mu.Lock()
			fmt.Printf("Errors: %d\tSuccess: %d\n", p.errorCount, p.successCount)
			p.mu.Unlock()
			time.Sleep(20 * time.Second)
		}
	}()
	wg.Wait()
}

func newPinger(remoteUrl string, maxConns int, timeout time.Duration) *pinger {
	return &pinger{
		client: http.Client{
			Transport: &http.Transport{
				MaxConnsPerHost: maxConns,
			},
			Timeout: timeout,
		},
		remoteUrl: remoteUrl,
	}
}

func main() {
	remoteURL := flag.String("r", "http://192.168.1.54:3000/info", "Remote URL")
	go func() {
		for {
			conns := fdexplorer.GetSummary()
			fmt.Println(conns)
			time.Sleep(30 * time.Second)
		}
	}()
	flag.Parse()
	fmt.Printf("Calling %s\n", *remoteURL)
	pinger := newPinger(*remoteURL, 10, 5*time.Second)
	pinger.run(20)
}
