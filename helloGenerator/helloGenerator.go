package helloGenerator

import (
	"crypto/sha256"
	"time"
)

type HelloGenerator struct {
}

type HelloMsg struct {
	Msg       string `json:"msg,omitempty"`
	Sha256    []byte `json:"sha_256,omitempty"`
	IssuedAt  int64  `json:"issued_at,omitempty"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
}

func Init() HelloGenerator {
	return HelloGenerator{}
}

func (s HelloGenerator) Get() HelloMsg {
	msgs := []string{
		"I met a traveller from an antique land",
		"Who said: Two vast and trunkless legs of stone",
		"Stand in the desart. Near them, on the sand",
		"Half sunk, a shattered visage lies, whose frown",
		"And wrinkled lip, and sneer of cold command",
		"Tell that its sculptor well those passions read",
		"Which yet survive, stamped on these lifeless things",
		"The hand that mocked them and the heart that fed:",
		"And on the pedestal these words appear:",
		"My name is Ozymandias, King of Kings:",
		"Look on my works, ye Mighty, and despair!",
		"No thing beside remains. Round the decay",
		"Of that colossal wreck, boundless and bare",
		"The lone and level sands stretch far away.",
		"— Percy Shelley, \"Ozymandias\", 1819 edition",
	}

	h := sha256.New()
	h.Write([]byte(msgs[9]))
	bs := h.Sum(nil)

	return HelloMsg{Msg: msgs[9], Sha256: bs, IssuedAt: time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Minute * 15).Unix()}

}
