package authMsgGenerator

import (
	"crypto/sha256"
	"time"
)

type AuthMsgGenerator struct {
}

type AuthMsg struct {
	Msg       string
	Sha256    []byte
	IssuedAt  int64
	ExpiresAt int64
}

func Init() AuthMsgGenerator {
	return AuthMsgGenerator{}
}

func (s AuthMsgGenerator) Get() AuthMsg {
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
	h.Write([]byte(msgs[10]))
	bs := h.Sum(nil)

	return AuthMsg{Msg: msgs[10], Sha256: bs, IssuedAt: time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Minute * 15).Unix()}

}
