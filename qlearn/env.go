package qlearn

import (
	"math/rand"
)

type Environment struct {
	// constant
	IDBlank   int
	IDRobot   int
	IDCrystal int

	// variable
	NAct             int
	Done             bool
	FieldLength      int
	CrystalCandidate []int
	RwdFail          float64
	RwdMove          float64
	RwdCrystal       float64
	RobotPos         int
	CrystalPos       int
	RobotState       string
}

func NewEnvironment() *Environment {
	return &Environment{
		// constant
		IDBlank:   0,
		IDRobot:   1,
		IDCrystal: 2,

		// variable
		NAct:             2,
		Done:             false,
		FieldLength:      4,
		CrystalCandidate: []int{2, 3},
		RwdFail:          -1.0,
		RwdMove:          -1.0,
		RwdCrystal:       5.0,
		RobotPos:         -1, // -1 instead of nil
		CrystalPos:       -1,
	}
}

func (e *Environment) Reset() []int {
	e.Done = false

	e.RobotState = "normal"
	e.RobotPos = 0

	idx := rand.Intn(len(e.CrystalCandidate))
	e.CrystalPos = e.CrystalCandidate[idx]

	obs := e.makeObs()
	return obs
}

func (e *Environment) makeObs() []int {
	if e.Done == true {
		obs := make([]int, e.FieldLength)
		for i := 0; i < e.FieldLength; i++ {
			obs[i] = 9
		}
		return obs
	}

	obs := make([]int, e.FieldLength)
	obs[e.CrystalPos] = e.IDCrystal
	obs[e.RobotPos] = e.IDRobot

	return obs
}

func (e *Environment) Step(act int) (rwd float64, done bool, obs []int) {
	if e.Done == true {
		obs := e.Reset()
		return -1, false, obs // -1 instead of None
	}

	var reward float64
	var isDone bool

	if act == 0 { // pick up
		if e.RobotPos == e.CrystalPos { // Robot picks up a crystal correctly.
			reward = e.RwdCrystal
			isDone = true
			e.RobotState = "success"
		} else { // Robot fail to picks up a crystal.
			reward = e.RwdFail
			isDone = true
			e.RobotState = "fail"
		}
	} else { // forward
		next_pos := e.RobotPos + 1

		if next_pos >= e.FieldLength { // Robot frward to wall.
			reward = e.RwdFail
			isDone = true
			e.RobotState = "fail"
		} else { // Robot forward to blank.
			e.RobotPos = next_pos
			reward = e.RwdMove
			isDone = false
			e.RobotState = "normal"
		}
	}

	e.Done = isDone
	obs = e.makeObs()
	return reward, isDone, obs
}
