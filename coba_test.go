package cobain

import (
	"fmt"
	"testing"

	"github.com/aiteung/atdb"
	"github.com/whatsauth/watoken"
	"go.mongodb.org/mongo-driver/bson"
)

// func TestUpdateGetData(t *testing.T) {
// 	mconn := SetConnection("MONGOSTRING", "pakarbi")
// 	datagedung := GetAllUser(mconn, "user")
// 	fmt.Println(datagedung)
// }

// }
// func TestGCFCreateHandler(t *testing.T) {
// 	// Simulate input parameters
// 	MONGOCONNSTRINGENV := "mongodb://raulgantengbanget:0nGCVlPPoCsXNhqG@ac-oilbpwk-shard-00-00.9ofhjs3.mongodb.net:27017,ac-oilbpwk-shard-00-01.9ofhjs3.mongodb.net:27017,ac-oilbpwk-shard-00-02.9ofhjs3.mongodb.net:27017/test?replicaSet=atlas-13x7kp-shard-0&ssl=true&authSource=admin"
// 	dbname := "petapedia"
// 	collectionname := "user"

// 	// Create a test User
// 	datauser := User{
// 		Username: "testuser",
// 		Password: "testpassword",
// 		Role:     "user",
// 	}

// 	// Call the handler function
// 	result := GCFCreateHandler(MONGOCONNSTRINGENV, dbname, collectionname, datauser)
// 	fmt.Println(result)
// 	// You can add assertions here to validate the result, or check the database for the created user.
// }

func TestCreateNewUserRole(t *testing.T) {
	var userdata User
	userdata.Username = "parkir"
	userdata.Password = "ulbi2"
	userdata.Role = "admin"
	mconn := SetConnection("MONGOSTRING", "pakarbi")
	CreateNewUserRole(mconn, "user", userdata)
}

func TestDeleteUser(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "pakarbi")
	var userdata User
	userdata.Username = "UserParkir"
	DeleteUser(mconn, "user", userdata)
}

func CreateNewUserToken(t *testing.T) {
	var userdata User
	userdata.Username = "pakarbi"
	userdata.Password = "ulbi2"
	userdata.Role = "admin"

	// Create a MongoDB connection
	mconn := SetConnection("MONGOSTRING", "pakarbi")

	// Call the function to create a user and generate a token
	err := CreateUserAndAddToken("your_private_key_env", mconn, "user", userdata)

	if err != nil {
		t.Errorf("Error creating user and token: %v", err)
	}
}

func TestGFCPostHandlerUser(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "pakarbi")
	var userdata User
	userdata.Username = "pakarbi"
	userdata.Password = "ulbi2"
	userdata.Role = "admin"
	CreateNewUserRole(mconn, "user", userdata)
}

func TestParkir(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "pakarbi")
	var parkirdata Parkir
	parkirdata.ID = 1
	parkirdata.Nopol = "D 3316 XGF"
	parkirdata.NamaMhs = "Faisal Ash"
	parkirdata.Prodi = "D4 Teknik Informatika"
	parkirdata.JenisKendaraan = "Honda Mio Z"
	parkirdata.WaktuMasuk = "07:24 AM"
	parkirdata.WaktuKeluar = "12:00 AM"
	parkirdata.Image = "https://www.google.com/url?sa=i&url=https%3A%2F%2Fwww.cermati.com%2Fkredit-motor%2Fyamaha-mio-z&psig=AOvVaw1hF-mRRLLYsX0eUybBN1Qu&ust=1699381551236000&source=images&cd=vfe&ved=0CBEQjRxqFwoTCMC1qN__r4IDFQAAAAAdAAAAABAE"
	CreateNewParkir(mconn, "parkir", parkirdata)
}

func TestAllParkir(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "pakarbi")
	parkir := GetAllParkir(mconn, "parkir")
	fmt.Println(parkir)
}

func TestGeneratePasswordHash(t *testing.T) {
	password := "ganteng"
	hash, _ := HashPassword(password) // ignore error for the sake of simplicity

	fmt.Println("Password:", password)
	fmt.Println("Hash:    ", hash)
	match := CheckPasswordHash(password, hash)
	fmt.Println("Match:   ", match)
}


func TestGeneratePrivateKeyPaseto(t *testing.T) {
	privateKey, publicKey := watoken.GenerateKey()
	fmt.Println(privateKey)
	fmt.Println(publicKey)
	hasil, err := watoken.Encode("anjay", privateKey)
	fmt.Println(hasil, err)
}


func TestHashFunction(t *testing.T) {
	mconn := SetConnection("mongodb+srv://faisalTampan:9byL9bOl3rhqbSrO@soren.uwshwr6.mongodb.net/test", "pakarbi")
	var userdata User
	userdata.Username = "anjay"
	userdata.Password = "tampan"

	filter := bson.M{"username": userdata.Username}
	res := atdb.GetOneDoc[User](mconn, "user", filter)
	fmt.Println("Mongo User Result: ", res)
	hash, _ := HashPassword(userdata.Password)
	fmt.Println("Hash Password : ", hash)
	match := CheckPasswordHash(userdata.Password, res.Password)
	fmt.Println("Match:   ", match)

}

func TestCreateUser(t *testing.T) {
	var userdata User
	userdata.Username = "anjay"
	userdata.Password = "tampan"
	userdata.Role = "admin"

	// Create a MongoDB connection
	mconn := SetConnection("MONGOSTRING", "pakarbi")

	// Call the function to create a user and generate a token
	err := CreateUser(mconn, "user", userdata)

	if err != nil {
		t.Errorf("Error creating user and token: %v", err)
	}
}

func TestIsPasswordValid(t *testing.T) {
	mconn := SetConnection("mongodb+srv://faisalTampan:9byL9bOl3rhqbSrO@soren.uwshwr6.mongodb.net/test", "pakarbi")
	var userdata User
	userdata.Username = "anjay"
	userdata.Password = "tampan"

	anu := IsPasswordValid(mconn, "user", userdata)
	fmt.Println(anu)
}

func TestUserFix(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "pakarbi")
	var userdata User
	userdata.Username = "faisal"
	userdata.Password = "tampan2"
	userdata.Role = "admin"
	CreateUser(mconn, "user", userdata)
}

func TestLoginn(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "pakarbi")
	var userdata User
	userdata.Username = "tes"
	userdata.Password = "testing"
	IsPasswordValid(mconn, "user", userdata)
	fmt.Println(userdata)
}

