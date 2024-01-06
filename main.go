package main

import (
	"flag"
	"fmt"
	"mk-lattigo/mkckks"
	"mk-lattigo/mkrlwe"
	"strconv"

	"github.com/ldsec/lattigo/v2/ckks"
	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/rlwe"
	"github.com/ldsec/lattigo/v2/utils"
)

var maxUsers = flag.Int("n", 4, "maximum number of parties")

// ckks parameters
var (
	PN15QP880 = ckks.ParametersLiteral{
		LogN:     15,
		LogSlots: 0, // default: 14
		//60 + 13x54
		Q: []uint64{
			0xfffffffff6a0001,

			0x3fffffffd60001, 0x3fffffffca0001,
			0x3fffffff6d0001, 0x3fffffff5d0001,
			0x3fffffff550001, 0x3fffffff390001,
			0x3fffffff360001, 0x3fffffff2a0001,
			0x3fffffff000001, 0x3ffffffefa0001,
			0x3ffffffef40001, 0x3ffffffed70001,
			0x3ffffffed30001,
		},
		P: []uint64{
			//59 x 2
			0x7ffffffffe70001, 0x7ffffffffe10001,
		},
		Scale: 1 << 54,
		Sigma: rlwe.DefaultSigma,
	}
	PN14QP439 = ckks.ParametersLiteral{
		LogN:     14,
		LogSlots: 13,
		Q: []uint64{
			// 59 + 5x52
			0x7ffffffffe70001,

			0xffffffff00001, 0xfffffffe40001,
			0xfffffffe20001, 0xfffffffbe0001,
			0xfffffffa60001,
		},
		P: []uint64{
			// 60 x 2
			0xffffffffffc0001, 0xfffffffff840001,
		},
		Scale: 1 << 52,
		Sigma: rlwe.DefaultSigma,
	}
)

type testParams struct {
	params mkckks.Parameters
	ringQ  *ring.Ring
	ringP  *ring.Ring
	prng   utils.PRNG
	kgen   *mkrlwe.KeyGenerator
	skSet  *mkrlwe.SecretKeySet
	pkSet  *mkrlwe.PublicKeySet
	rlkSet *mkrlwe.RelinearizationKeySet
	rtkSet *mkrlwe.RotationKeySet
	cjkSet *mkrlwe.ConjugationKeySet

	encryptor *mkckks.Encryptor
	decryptor *mkckks.Decryptor
	evaluator *mkckks.Evaluator
	idset     *mkrlwe.IDSet
}

func genTestParams(defaultParam mkckks.Parameters, idset *mkrlwe.IDSet) (testContext *testParams, err error) {

	testContext = new(testParams)

	testContext.params = defaultParam

	testContext.kgen = mkckks.NewKeyGenerator(testContext.params)

	testContext.skSet = mkrlwe.NewSecretKeySet()
	testContext.pkSet = mkrlwe.NewPublicKeyKeySet()
	testContext.rlkSet = mkrlwe.NewRelinearizationKeyKeySet(defaultParam.Parameters)
	testContext.rtkSet = mkrlwe.NewRotationKeySet()
	testContext.cjkSet = mkrlwe.NewConjugationKeySet()

	// gen sk, pk, rlk, rk

	for id := range idset.Value {
		sk, pk := testContext.kgen.GenKeyPair(id)
		r := testContext.kgen.GenSecretKey(id)
		rlk := testContext.kgen.GenRelinearizationKey(sk, r)
		//cjk := testContext.kgen.GenConjugationKey(sk)

		//testContext.kgen.GenDefaultRotationKeys(sk, testContext.rtkSet)

		testContext.skSet.AddSecretKey(sk)
		testContext.pkSet.AddPublicKey(pk)
		testContext.rlkSet.AddRelinearizationKey(rlk)
		//testContext.cjkSet.AddConjugationKey(cjk)

	}

	testContext.ringQ = defaultParam.RingQ()

	if testContext.prng, err = utils.NewPRNG(); err != nil {
		return nil, err
	}

	testContext.encryptor = mkckks.NewEncryptor(testContext.params)
	testContext.decryptor = mkckks.NewDecryptor(testContext.params)

	testContext.evaluator = mkckks.NewEvaluator(testContext.params)

	return testContext, nil

}

func main() {
	flag.Parse()

	ckksParams, err := ckks.NewParametersFromLiteral(PN15QP880) // 128 bit security
	if err != nil {
		panic(err)
	}

	params := mkckks.NewParameters(ckksParams)
	userList := make([]string, *maxUsers)
	idset := mkrlwe.NewIDSet()

	for i := range userList {
		userList[i] = "user" + strconv.Itoa(i)
		idset.Add(userList[i])
	}

	for i := range userList {
		userList[i] = "user" + strconv.Itoa(i)
		idset.Add(userList[i])
	}

	var testContext *testParams
	if testContext, err = genTestParams(params, idset); err != nil {
		panic(err)
	}

	testEncAndDec(testContext, userList)
}

func testEncAndDec(testContext *testParams, userList []string) {
	numUsers := len(userList)
	msgList := make([]*mkckks.Message, numUsers)
	ctList := make([]*mkckks.Ciphertext, numUsers)

	skSet := testContext.skSet
	dec := testContext.decryptor

	for i := range userList {
		msgList[i], ctList[i] = generatePlaintextAndCiphertext(testContext, userList[i], complex(-1, 0), complex(1, 0))
	}

	user1 := "user1"
	user2 := "user2"
	idset1 := mkrlwe.NewIDSet()
	idset2 := mkrlwe.NewIDSet()
	idset1.Add(user1)
	idset2.Add(user2)

	ct3 := testContext.evaluator.AddNew(ctList[0], ctList[1])
	ct4 := testContext.evaluator.MulRelinNew(ctList[0], ctList[1], testContext.rlkSet)

	//testContext.evaluator.MultByConst(ct3, constant, ct3)
	//ct3.Scale *= float64(constant)
	//testContext.evaluator.Rescale(ct3, params.Scale(), ct3)
	msg3Out := testContext.decryptor.Decrypt(ct3, testContext.skSet)
	msg4Out := testContext.decryptor.Decrypt(ct4, testContext.skSet)

	fmt.Println("Enc and Dec without any calculation")
	for i := range userList {
		msgOut := dec.Decrypt(ctList[i], skSet)
		fmt.Printf("user-%d:\nplaintext: %g,\ndecrypted: %g\n", i, msgList[i], msgOut)
	}

	fmt.Println("Add: user1 + user2")
	fmt.Println(msg3Out)
	fmt.Println("Mul: user1 * user2")
	fmt.Println(msg4Out)
}

func generatePlaintextAndCiphertext(testContext *testParams, id string, a, b complex128) (msg *mkckks.Message, ciphertext *mkckks.Ciphertext) {

	params := testContext.params
	logSlots := testContext.params.LogSlots()

	msg = mkckks.NewMessage(params)

	for i := 0; i < 1<<logSlots; i++ {
		msg.Value[i] = complex(utils.RandFloat64(real(a), real(b)), utils.RandFloat64(imag(a), imag(b)))
	}

	if testContext.encryptor != nil {
		ciphertext = testContext.encryptor.EncryptMsgNew(msg, testContext.pkSet.GetPublicKey(id))
	} else {
		panic("cannot newTestVectors: encryptor is not initialized!")
	}

	return msg, ciphertext
}
