package helloGenerator

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"time"
)

type Wisdom struct {
	Author      string `json:"author,omitempty"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	Link        string `json:"link,omitempty"`
}

type HelloMsg struct {
	Msg    string `json:"msg,omitempty"`
	Sha256 []byte `json:"sha_256,omitempty"`
	Wisdom
	IssuedAt  int64 `json:"issued_at,omitempty"`
	ExpiresAt int64 `json:"expires_at,omitempty"`
}

type Quote struct {
	msg    string
	wisdom *Wisdom
}

type HelloGenerator struct {
	wisdoms []Wisdom
	msgs    []Quote
}

func Create() HelloGenerator {
	return HelloGenerator{}
}

func (h *HelloGenerator) Load(helloFolder string, numWisdoms int) {
	wisdomPath := ""
	manifestPath := ""
	h.wisdoms = make([]Wisdom, 0, numWisdoms)

	for i := range numWisdoms {
		wisdomPath = fmt.Sprintf("%s/%d/content", helloFolder, i+1)
		manifestPath = fmt.Sprintf("%s/%d/manifest", helloFolder, i+1)
		manifest, err := os.ReadFile(manifestPath)
		if err != nil {
			panic("Could not load manifest file : " + manifestPath + ", error : " + err.Error())
		}

		wisdom := Wisdom{}

		if json.Unmarshal(manifest, &wisdom) != nil {
			panic("Could not unmarshal manifest file to wisdom : " + manifestPath)
		}
		h.wisdoms = append(h.wisdoms, wisdom)

		file, err := os.Open(wisdomPath)
		if err != nil {
			panic("Could not Open wisdom path : " + wisdomPath + ", err : " + err.Error())
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			h.msgs = append(h.msgs, Quote{scanner.Text(), &h.wisdoms[len(h.wisdoms)-1]})

		}

		if err := scanner.Err(); err != nil {
			panic("Wrong state of scaner : " + err.Error())
		}
		file.Close()

	}
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(h.msgs), func(i, j int) {
		h.msgs[i], h.msgs[j] = h.msgs[j], h.msgs[i]
	})

}

func (h *HelloGenerator) Get() HelloMsg {
	len := len(h.msgs)
	index := rand.Intn(len)

	quote := h.msgs[index]

	s := sha256.New()
	s.Write([]byte(quote.msg))
	bs := s.Sum(nil)

	return HelloMsg{Msg: quote.msg, Sha256: bs, Wisdom: *quote.wisdom, IssuedAt: time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Minute * 15).Unix()}

}
