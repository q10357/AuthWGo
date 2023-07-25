package data

import "time"

//Struct for user data
type user struct {
	id       uint64
	email    string
	username string
	//server will not know plaintext password, encrypted on client
	passwordhash string
	createdAt    string
	//role is 0 => standard user
	role int
}

//Faking database
var userList = []user{
	{
		id:           1,
		email:        "issi@gmail.com",
		username:     "issichik",
		passwordhash: "hashedme1",
		createdAt:    "1631600786",
		role:         1,
	},
	{
		id:           2,
		email:        "checkers@example.com",
		username:     "checkers",
		passwordhash: "hashedme2",
		createdAt:    "1631600837",
		role:         0,
	},
}

//Get user by unique email
func GetUserObject(email string) (user, bool) {
	for _, user := range userList {
		if user.email == email {
			//Match!
			return user, true
		}
	}

	//No match, return false
	return user{}, false
}

func (u *user) CheckIfAdmin() bool {
	return u.role == 1
}

func (u *user) GetUserId() uint64 {
	return u.id
}

//Function belonging to user struct
func (u *user) ValidatePasswordHash(pswdhash string) bool {
	return u.passwordhash == pswdhash
}

//Adds new users
func AddNewUserObject(email string, username string, passwordhash string, role int) bool {
	//declare new object
	newUser := user{
		email:        email,
		passwordhash: passwordhash,
		username:     username,
		createdAt:    time.Now().String(),
		role:         role,
	}

	//Check if user exists
	for _, u := range userList {
		if u.email == email || u.username == username {
			return false
		}
	}

	userList = append(userList, newUser)
	return true
}
