package qlearn

import (
	"mk-lattigo/mkckks"
	"mk-lattigo/pprl"
	"mk-lattigo/utils"
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

func (e *Agent) Learn(s int, act int, rwd float64, next_s int, testContext *utils.TestParams, encryptedQtable []*mkckks.Ciphertext, user_list []string) {
	e.checkAndAddObservation(s)
	e.checkAndAddObservation(next_s)

	target := float64(0)
	target = rwd + e.Gamma*maxValue(e.Q[next_s])

	e.Q[s][act] = (1-e.Alpha)*e.Q[s][act] + e.Alpha*target

	Qnew := e.Q[s][act]
	v_t := make([]float64, e.LenQ)
	w_t := make([]float64, e.Nact)
	v_t[s] = 1
	w_t[act] = 1
	pprl.SecureQtableUpdating(v_t, w_t, Qnew, e.LenQ, e.Nact, testContext, encryptedQtable, user_list)
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

func maxValue(slice []float64) float64 {
	maxValue := slice[0]
	for _, v := range slice {
		if v > maxValue {
			maxValue = v
		}
	}
	return maxValue
}
