package main

import (
	"encoding/csv"
	"fmt"
	"mk-lattigo/mkckks"
	"mk-lattigo/mkrlwe"
	"mk-lattigo/qlearn"
	"mk-lattigo/utils"
	"os"
	"path/filepath"
	"strconv"

	"github.com/ldsec/lattigo/v2/ckks"
)

var (
	MAX_USERS   = 2
	MAX_ACTIONS = 503
)

func main() {
	ckks_params, err := ckks.NewParametersFromLiteral(utils.PN14QP439) // 128 bit security
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

	dirname := "./dataset/preprocessed_diabetes_SRL_dataset"

	files, err := os.ReadDir(dirname)
	if err != nil {
		panic(err)
	}

	// クラウドのQ値を初期化
	encryptedQtable := make([]*mkckks.Ciphertext, Agt.LenQ)
	for i := 0; i < Agt.LenQ; i++ {
		plaintext := mkckks.NewMessage(testContext.Params)
		for i := 0; i < 1<<testContext.Params.LogSlots(); i++ {
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

		for _, record := range records {
			status, _ := strconv.Atoi(record[1])
			action, _ := strconv.Atoi(record[2])
			rwd, _ := strconv.ParseFloat(record[3], 64)
			next_status, _ := strconv.Atoi(record[4])

			fmt.Println(status, action, rwd, next_status)
			// Agt.Learn(status, action, rwd, next_status, ckksKeyTools, encryptedQtable)
		}
	}
}
