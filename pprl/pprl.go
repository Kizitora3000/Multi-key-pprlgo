package pprl

import (
	"mk-lattigo/mkckks"
	"mk-lattigo/utils"
)

func initializeZeros(Na int, params mkckks.Parameters) *mkckks.Message {
	zeros := mkckks.NewMessage(params)
	for i := 0; i < Na; i++ {
		zeros.Value[i] = complex(0, 0)
	}
	return zeros
}

func initializeOnes(Na int, params mkckks.Parameters) *mkckks.Message {
	ones := mkckks.NewMessage(params)
	for i := 0; i < Na; i++ {
		ones.Value[i] = complex(0, 0)
	}
	return ones
}

func SecureQtableUpdating(v_t []float64, w_t []float64, Q_new float64, Nv int, Na int, testContext *utils.TestParams, EncryptedQtable []*mkckks.Ciphertext, user_list []string) {
	temp := make([]*mkckks.Ciphertext, Nv)

	for i := 0; i < Nv; i++ {
		if v_t[i] == 0 {
			zeros := initializeZeros(Na, testContext.Params)
			temp[i] = testContext.Encryptor.EncryptMsgNew(zeros, testContext.PkSet.GetPublicKey(user_list[1])) // user_list[1] = "user1"
		} else if v_t[i] == 1 {
			ones := initializeZeros(Na, testContext.Params)
			temp[i] = testContext.Encryptor.EncryptMsgNew(ones, testContext.PkSet.GetPublicKey(user_list[1])) // user_list[1] = "user1"
		}
	}

	w_t_msg := mkckks.NewMessage(testContext.Params)
	for i := 0; i < Na; i++ {
		w_t_msg.Value[i] = complex(w_t[i], 0) // 虚部は0
	}
	fhe_w_t := testContext.Encryptor.EncryptMsgNew(w_t_msg, testContext.PkSet.GetPublicKey(user_list[1])) // user_list[1] = "user1"

	Q_news_msg := mkckks.NewMessage(testContext.Params)
	for i := 0; i < Na; i++ {
		Q_news_msg.Value[i] = complex(Q_new, 0) // 虚部は0
	}
	fhe_Q_news := testContext.Encryptor.EncryptMsgNew(w_t_msg, testContext.PkSet.GetPublicKey(user_list[1])) // user_list[1] = "user1"

	for i := 0; i < Nv; i++ {
		fhe_v_t := temp[i]

		// make Qnew
		fhe_v_and_w_Qnew := testContext.Evaluator.MulRelinNew(fhe_v_t, fhe_w_t, testContext.RlkSet)
		fhe_v_and_w_Qnew = testContext.Evaluator.MulRelinNew(fhe_v_and_w_Qnew, fhe_Q_news, testContext.RlkSet)

		// make Qold
		fhe_v_and_w_Qold := testContext.Evaluator.MulRelinNew(fhe_v_t, fhe_w_t, testContext.RlkSet)
		fhe_v_and_w_Qold = testContext.Evaluator.MulRelinNew(fhe_v_and_w_Qold, EncryptedQtable[i], testContext.RlkSet)

		/*
			decrypt_fhe_v_and_w_Qnew := doublenc.FHEdec(params, encoder, decryptor, fhe_v_and_w_Qnew)
			realValues1 := make([]float64, len(decrypt_fhe_v_and_w_Qnew))
			for i, v := range decrypt_fhe_v_and_w_Qnew {
				realValues1[i] = real(v)
			}
			re_fhe_v_and_w_Qnew := doublenc.FHEenc(params, encoder, encryptor, realValues1)

			decrypt_fhe_v_and_w_Qold := doublenc.FHEdec(params, encoder, decryptor, fhe_v_and_w_Qold)
			realValues2 := make([]float64, len(decrypt_fhe_v_and_w_Qold))
			for i, v := range decrypt_fhe_v_and_w_Qold {
				realValues2[i] = real(v)
			}
			re_fhe_v_and_w_Qold := doublenc.FHEenc(params, encoder, encryptor, realValues2)
		*/

		// EncryptedQtalbe[i]がノイズで爆発する
		EncryptedQtable[i] = testContext.Evaluator.AddNew(EncryptedQtable[i], fhe_v_and_w_Qnew)
		EncryptedQtable[i] = testContext.Evaluator.SubNew(EncryptedQtable[i], fhe_v_and_w_Qold)
	}

}
