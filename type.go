package cobain

// import "go.mongodb.org/mongo-driver/bson/primitive"

type User struct {
	Username string `json:"username" bson:"username"`
	Password string `json:"password" bson:"password"`
	Role     string `json:"role,omitempty" bson:"role,omitempty"`
	Token    string `json:"token,omitempty" bson:"token,omitempty"`
	Private  string `json:"private,omitempty" bson:"private,omitempty"`
	Publick  string `json:"publick,omitempty" bson:"publick,omitempty"`
}

type Credential struct {
	Status  bool   `json:"status" bson:"status"`
	Token   string `json:"token,omitempty" bson:"token,omitempty"`
	Message string `json:"message,omitempty" bson:"message,omitempty"`
}

type Parkir struct {
	ID          		  	int 			   `bson:"_id,omitempty" `
	Nopol     			  	string             `json:"nopol" bson:"nopol"`
	NamaMhs       		  	string             `json:"namamhs" bson:"namamhs"`
	Prodi        		  	string             `json:"prodi" bson:"prodi"`
	JenisKendaraan        	string             `json:"jeniskendaraan" bson:"jeniskendaraan"`
	WaktuMasuk 		  		string             `json:"waktumasuk" bson:"waktumasuk"`
	WaktuKeluar       		string             `json:"waktukeluar" bson:"waktukeluar"`
	Image       			string             `json:"image" bson:"image"`
}

type Response struct {
	Status  bool        `json:"status" bson:"status"`
	Message string      `json:"message" bson:"message"`
	Data    interface{} `json:"data" bson:"data"`
}

type CodeQr struct {
	ID          	string `bson:"id,omitempty" `
	Message 		string `json:"message" bson:"message"`
	Email			string `json:"email" bson:"email"`
	Notification	string `json:"notification" bson:"notification"`
}

type Iklan struct {
	ID          int    `json:"id" bson:"id"`
	Title       string `json:"title" bson:"title"`
	Description string `json:"description" bson:"description"`
	Image       string `json:"image" bson:"image"`
}
