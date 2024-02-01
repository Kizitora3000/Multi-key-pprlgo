package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"mk-lattigo/mkckks"
	"mk-lattigo/mkrlwe"
	"mk-lattigo/qlearn"
	"mk-lattigo/utils"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/ldsec/lattigo/v2/ckks"
)

var (
	MAX_USERS   = 2
	MAX_ACTIONS = 503
)

func main() {
	// 128 bit security
	// ckks_params, err := ckks.NewParametersFromLiteral(utils.PN14QP439)

	// Q値の確認用(pprlと同じかどうか)
	ckks_params, err := ckks.NewParametersFromLiteral(utils.FAST_BUT_NOT_128)
	if err != nil {
		panic(err)
	}

	params := mkckks.NewParameters(ckks_params)
	user_list := make([]string, MAX_USERS)
	idset := mkrlwe.NewIDSet()

	user_list[0] = "cloud"
	user_list[1] = "user1"

	for i := range user_list {
		idset.Add(user_list[i])
	}

	var testContext *utils.TestParams
	if testContext, err = utils.GenTestParams(params, idset); err != nil {
		panic(err)
	}

	Agt := qlearn.NewAgent()
	Agt.LenQ = MAX_ACTIONS

	dirname := "preprocessed_diabetes_SRL_dataset"

	files, err := os.ReadDir(dirname)
	if err != nil {
		panic(err)
	}

	// クラウドのQ値を初期化
	encryptedQtable := make([]*mkckks.Ciphertext, Agt.LenQ)
	for i := 0; i < Agt.LenQ; i++ {
		plaintext := mkckks.NewMessage(testContext.Params)
		for i := 0; i < (1 << testContext.Params.LogSlots()); i++ {
			plaintext.Value[i] = complex(Agt.InitValQ, 0) // 虚部は0
		}

		ciphertext := testContext.Encryptor.EncryptMsgNew(plaintext, testContext.PkSet.GetPublicKey(user_list[0])) // user_list[0] = "cloud"
		encryptedQtable[i] = ciphertext
	}

	for _, file := range files {
		fmt.Println(file)
		filename := filepath.Join(dirname, file.Name())
		file, err := os.Open(filename)

		// open csv
		if err != nil {
			fmt.Printf("Error opening file %s: %v\n", filename, err)
			return
		}
		defer file.Close()

		r := csv.NewReader(file)
		records, err := r.ReadAll()
		if err != nil {
			fmt.Printf("Error reading CSV %s: %v\n", filename, err)
			return
		}

		// Exclude the last row
		records = records[:len(records)-1]

		for i, record := range records {
			if i == 0 {
				// 1行目はカラムの情報なのでスキップ
				continue
			}

			startTime := time.Now()

			status, _ := strconv.Atoi(record[1])
			action, _ := strconv.Atoi(record[2])
			rwd, _ := strconv.ParseFloat(record[3], 64)
			next_status_float, _ := strconv.ParseFloat(record[4], 64)
			next_status := int(next_status_float)
			// next_status, _ := strconv.Atoi(record[4])
			Agt.Learn(status, action, rwd, next_status, testContext, encryptedQtable, user_list)

			duration := time.Since(startTime)
			fmt.Printf("file: %s\tindex:%d\ttime:%s\n", file.Name(), i, duration)
		}
	}

	// 暗号化したQテーブルのQ値
	Qtable := [][]float64{}
	for i := 0; i < Agt.LenQ; i++ {
		plaintext := testContext.Decryptor.Decrypt(encryptedQtable[i], testContext.SkSet)
		plaintext_real := make([]float64, Agt.Nact)
		for j := 0; j < Agt.Nact; j++ {
			if j == Agt.Nact {
				continue
			}
			plaintext_real[j] = real(plaintext.Value[j])

		}
		Qtable = append(Qtable, plaintext_real)
	}

	jsonData, err := json.Marshal(Qtable)
	if err != nil {
		fmt.Println(err)
		return
	}

	err = ioutil.WriteFile("pprl_data.json", jsonData, 0644)
	if err != nil {
		fmt.Println(err)
	}

	// ユーザ側のQ値
	AgtQtable := [][]float64{}
	for i := 0; i < Agt.LenQ; i++ {
		if _, isExist := Agt.Q[i]; !isExist {
			Agt.Q[i] = make([]float64, Agt.Nact)
			for j := 0; j < Agt.Nact; j++ {
				Agt.Q[i][j] = Agt.InitValQ
			}
		}

		AgtQtable = append(AgtQtable, Agt.Q[i])
	}

	AgtjsonData, err := json.Marshal(AgtQtable)
	if err != nil {
		fmt.Println(err)
		return
	}

	err = ioutil.WriteFile("rl_data.json", AgtjsonData, 0644)
	if err != nil {
		fmt.Println(err)
	}
}
