package cobain

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/aiteung/atdb"
	"github.com/whatsauth/watoken"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func SetConnection(MONGOCONNSTRINGENV, dbname string) *mongo.Database {
	var DBmongoinfo = atdb.DBInfo{
		DBString: os.Getenv(MONGOCONNSTRINGENV),
		DBName:   dbname,
	}
	return atdb.MongoConnect(DBmongoinfo)
}

// func GetAllBangunanLineString(mongoconn *mongo.Database, collection string) []GeoJson {
// 	lokasi := atdb.GetAllDoc[[]GeoJson](mongoconn, collection)
// 	return lokasi
// }

func CreateUser(mongoconn *mongo.Database, collection string, userdata User) interface{} {
	// Hash the password before storing it
	hashedPassword, err := HashPassword(userdata.Password)
	if err != nil {
		return err
	}
	privateKey, publicKey := watoken.GenerateKey()
	userid := userdata.Username
	tokenstring, err := watoken.Encode(userid, privateKey)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(tokenstring)
	// decode token to get userid
	useridstring := watoken.DecodeGetId(publicKey, tokenstring)
	if useridstring == "" {
		fmt.Println("expire token")
	}
	fmt.Println(useridstring)
	userdata.Private = privateKey
	userdata.Publick = publicKey
	userdata.Password = hashedPassword

	// Insert the user data into the database
	return atdb.InsertOneDoc(mongoconn, collection, userdata)
}

// func GetAllProduct(mongoconn *mongo.Database, collection string) []Product {
// 	product := atdb.GetAllDoc[[]Product](mongoconn, collection)
// 	return product
// }

// func GetNameAndPassowrd(mongoconn *mongo.Database, collection string) []User {
// 	user := atdb.GetAllDoc[[]User](mongoconn, collection)
// 	return user
// }

// func GetAllContent(mongoconn *mongo.Database, collection string) []Content {
// 	content := atdb.GetAllDoc[[]Content](mongoconn, collection)
// 	return content
// }

//	func GetAllUser(mongoconn *mongo.Database, collection string) []User {
//		user := atdb.GetAllDoc[[]User](mongoconn, collection)
//		return user
//	}
func CreateNewUserRole(mongoconn *mongo.Database, collection string, userdata User) interface{} {
	// Hash the password before storing it
	hashedPassword, err := HashPassword(userdata.Password)
	if err != nil {
		return err
	}
	userdata.Password = hashedPassword

	// Insert the user data into the database
	return atdb.InsertOneDoc(mongoconn, collection, userdata)
}
func CreateUserAndAddedToeken(PASETOPRIVATEKEYENV string, mongoconn *mongo.Database, collection string, userdata User) interface{} {
	// Hash the password before storing it
	hashedPassword, err := HashPassword(userdata.Password)
	if err != nil {
		return err
	}
	userdata.Password = hashedPassword

	// Insert the user data into the database
	atdb.InsertOneDoc(mongoconn, collection, userdata)

	// Create a token for the user
	tokenstring, err := watoken.Encode(userdata.Username, os.Getenv(PASETOPRIVATEKEYENV))
	if err != nil {
		return err
	}
	userdata.Token = tokenstring

	// Update the user data in the database
	return atdb.ReplaceOneDoc(mongoconn, collection, bson.M{"username": userdata.Username}, userdata)
}

func DeleteUser(mongoconn *mongo.Database, collection string, userdata User) interface{} {
	filter := bson.M{"username": userdata.Username}
	return atdb.DeleteOneDoc(mongoconn, collection, filter)
}
func ReplaceOneDoc(mongoconn *mongo.Database, collection string, filter bson.M, userdata User) interface{} {
	return atdb.ReplaceOneDoc(mongoconn, collection, filter, userdata)
}
func FindUser(mongoconn *mongo.Database, collection string, userdata User) User {
	filter := bson.M{"username": userdata.Username}
	return atdb.GetOneDoc[User](mongoconn, collection, filter)
}

func FindUserUser(mongoconn *mongo.Database, collection string, userdata User) User {
	filter := bson.M{
		"username": userdata.Username,
	}
	return atdb.GetOneDoc[User](mongoconn, collection, filter)
}

func FindUserUserr(mongoconn *mongo.Database, collection string, userdata User) (User, error) {
	filter := bson.M{
		"username": userdata.Username,
	}

	var user User
	err := mongoconn.Collection(collection).FindOne(context.Background(), filter).Decode(&user)
	if err != nil {
		return User{}, err
	}

	return user, nil
}

func IsPasswordValid(mongoconn *mongo.Database, collection string, userdata User) bool {
	filter := bson.M{"username": userdata.Username}
	res := atdb.GetOneDoc[User](mongoconn, collection, filter)
	return CheckPasswordHash(userdata.Password, res.Password)
}

func IsPasswordValidd(mconn *mongo.Database, collection string, userdata User) (User, bool) {
	filter := bson.M{"username": userdata.Username}
	var foundUser User
	err := mconn.Collection(collection).FindOne(context.Background(), filter).Decode(&foundUser)
	if err != nil {
		return User{}, false
	}
	// Verify password here
	if CheckPasswordHash(userdata.Password, foundUser.Password) {
		return foundUser, true
	}
	return User{}, false
}

// Parkir

func CreateNewParkir(mongoconn *mongo.Database, collection string, parkirdatadata Parkir) interface{} {
	return atdb.InsertOneDoc(mongoconn, collection, parkirdatadata)
}
func GetAllParkir(mongoconn *mongo.Database, collection string) []Parkir {
	parkir := atdb.GetAllDoc[[]Parkir](mongoconn, collection)
	return parkir
}

// ScanQR
func CreateNewScanQR(mconn *mongo.Client, collectionName string, qrdata CodeQr) error {
	collection := mconn.Database("pakarbi").Collection(collectionName)
	_, err := collection.InsertOne(context.Background(), qrdata)
	if err != nil {
		return err
	}
	return nil
}

func createNewScanQR(email string) *CodeQr {
	// Generate a random QR code message (you can use your logic here)
	qrMessage := generateRandomQRMessage()

	// Create a new CodeQr instance
	qr := &CodeQr{
		Message:      qrMessage,
		Email:        email,
		Notification: "Scan this QR code within 2 minutes",
	}

	// Set a timer for 2 minutes
	go func() {
		timer := time.NewTimer(2 * time.Minute)
		<-timer.C

		// After 2 minutes, you can perform any action like deleting the QR code
		// For this example, we'll print a message
		fmt.Println("QR code has expired")
	}()

	return qr
}

func generateRandomQRMessage() string {
	// Generate a random QR code message logic goes here
	return "Your_Random_QR_Message"
}

func CreateUserAndAddToken(privateKeyEnv string, mongoconn *mongo.Database, collection string, userdata User) error {
	// Hash the password before storing it
	hashedPassword, err := HashPassword(userdata.Password)
	if err != nil {
		return err
	}
	userdata.Password = hashedPassword

	// Create a token for the user
	tokenstring, err := watoken.Encode(userdata.Username, os.Getenv(privateKeyEnv))
	if err != nil {
		return err
	}

	userdata.Token = tokenstring

	// Insert the user data into the MongoDB collection
	if err := atdb.InsertOneDoc(mongoconn, collection, userdata.Username); err != nil {
		return nil // Mengembalikan kesalahan yang dikembalikan oleh atdb.InsertOneDoc
	}

	// Return nil to indicate success
	return nil
}

func AuthenticateUserAndGenerateToken(privateKeyEnv string, mongoconn *mongo.Database, collection string, userdata User) (string, error) {
	// Cari pengguna berdasarkan nama pengguna
	username := userdata.Username
	password := userdata.Password
	userdata, err := FindUserByUsername(mongoconn, collection, username)
	if err != nil {
		return "", err
	}

	// Memeriksa kata sandi
	if !CheckPasswordHash(password, userdata.Password) {
		return "", errors.New("Password salah") // Gantilah pesan kesalahan sesuai kebutuhan Anda
	}

	// Generate token untuk otentikasi
	tokenstring, err := watoken.Encode(username, os.Getenv(privateKeyEnv))
	if err != nil {
		return "", err
	}

	return tokenstring, nil
}

func FindUserByUsername(mongoconn *mongo.Database, collection string, username string) (User, error) {
	var user User
	filter := bson.M{"username": username}
	err := mongoconn.Collection(collection).FindOne(context.TODO(), filter).Decode(&user)
	if err != nil {
		return User{}, err
	}
	return user, nil
}

// create login using Private
func CreateLogin(mongoconn *mongo.Database, collection string, userdata User) interface{} {
	// Hash the password before storing it
	hashedPassword, err := HashPassword(userdata.Password)
	if err != nil {
		return err
	}
	userdata.Password = hashedPassword
	// Create a token for the user
	tokenstring, err := watoken.Encode(userdata.Username, userdata.Private)
	if err != nil {
		return err
	}
	userdata.Token = tokenstring

	// Insert the user data into the database
	return atdb.InsertOneDoc(mongoconn, collection, userdata)
}

