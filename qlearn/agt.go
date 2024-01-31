package qlearn

import (
	"strconv"
	"strings"

	"github.com/ldsec/lattigo/v2/rlwe"
)

type Agent struct {
	Nact     int
	InitValQ float64
	Epsilon  float64
	Alpha    float64
	Gamma    float64
	Q        map[int][]float64
	LenQ     int
}

func NewAgent() *Agent {
	return &Agent{
		Nact:     63,   // 投与の最大値
		InitValQ: -1e3, // なるべく負の値を小さくするのが目的
		Epsilon:  0.1,
		Alpha:    0.1,
		Gamma:    0.9,
		Q:        map[int][]float64{},
		LenQ:     0,
	}
}

func (e *Agent) Learn(s int, act int, rwd float64, next_s int, encryptedQtable []*rlwe.Ciphertext) {
	e.checkAndAddObservation(s)
	e.checkAndAddObservation(next_s)

	target := float64(0)
	target = rwd + e.Gamma*maxValue(e.Q[next_s])

	e.Q[s][act] = (1-e.Alpha)*e.Q[s][act] + e.Alpha*target

	// Qnew := e.Q[s][act]
	v_t := make([]float64, e.LenQ) // マジックナンバー とりあえずUCIのデータセットの血糖値は最大で501
	w_t := make([]float64, e.Nact)
	v_t[s] = 1
	w_t[act] = 1
	//pprl.SecureQtableUpdating(keyTools.Params, keyTools.Encoder, keyTools.Encryptor, keyTools.Decryptor, keyTools.Evaluator, keyTools.PublicKey, keyTools.PrivateKey, v_t, w_t, Qnew, e.LenQ, e.Nact, encryptedQtable)
}

func (e *Agent) Learn_BFV(s int, act int, rwd float64, next_s int, encryptedQtable []*rlwe.Ciphertext) {
	e.checkAndAddObservation(s)
	e.checkAndAddObservation(next_s)

	target := float64(0)
	target = rwd + e.Gamma*maxValue(e.Q[next_s])

	e.Q[s][act] = (1-e.Alpha)*e.Q[s][act] + e.Alpha*target

	// Qnew := uint64(e.Q[s][act] * 1000) // 係数でとりあえず 1000掛けとく
	v_t := make([]uint64, e.LenQ) // マジックナンバー とりあえずUCIのデータセットの血糖値は最大で501
	w_t := make([]uint64, e.Nact)
	v_t[s] = 1
	w_t[act] = 1
	// pprl.SecureQtableUpdatingWithBFV(keyTools.Params, keyTools.Encoder, keyTools.Encryptor, keyTools.Decryptor, keyTools.Evaluator, keyTools.PublicKey, keyTools.PrivateKey, v_t, w_t, Qnew, e.LenQ, e.Nact, encryptedQtable)
}

func (e *Agent) GetQ(s int) []float64 {

	Q := []float64{}

	if _, isExist := e.Q[s]; isExist {
		Q = e.Q[s]
	} else {
		Q = nil
	}

	return Q
}

func (e *Agent) toStr(obs []int) string {
	strs := make([]string, len(obs))

	for i, o := range obs {
		strs[i] = strconv.Itoa(o)
	}
	return strings.Join(strs, ",")
}

func (e *Agent) checkAndAddObservation(s int) {
	if _, isExist := e.Q[s]; !isExist {
		e.Q[s] = make([]float64, e.Nact)
		for i := 0; i < e.Nact; i++ {
			e.Q[s][i] = e.InitValQ
		}
		// e.LenQ++
	}
}

func maxIdx(slice []float64) int {
	maxIndex := 0
	maxValue := slice[0]
	for i, v := range slice {
		if v > maxValue {
			maxValue = v
			maxIndex = i
		}
	}
	return maxIndex
}

func maxValue(slice []float64) float64 {
	maxValue := slice[0]
	for _, v := range slice {
		if v > maxValue {
			maxValue = v
		}
	}
	return maxValue
}
