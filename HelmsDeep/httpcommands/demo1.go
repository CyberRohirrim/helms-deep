package httpcommands

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

func homePage(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Welcome to server")
}

type User struct {
	Id          string `json:"id"`
	UserName    string `json:"userName"`
	UserPwd     string `json:"userPwd"`
	AuthorityId int    `json:"authorityId"`
}
type Authority struct {
	Id            int `json:"id"`
	AuthorityName int `json:"authorityName"`
}

var Users []User

func allUsers(w http.ResponseWriter, r *http.Request) {

	json.NewEncoder(w).Encode(Users)
}

func getOneUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	key := vars["id"]

	for _, user := range Users {
		if user.Id == key {
			json.NewEncoder(w).Encode(user)
		}
	}
	fmt.Fprintf(w, "Key: "+key)

}

func newUser(w http.ResponseWriter, r *http.Request) {
	requestBody, _ := ioutil.ReadAll(r.Body)
	var user User
	json.Unmarshal(requestBody, &user)
	Users = append(Users, user)

	json.NewEncoder(w).Encode(user)
}

func deleteUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	key := vars["id"]

	for i, user := range Users {
		if user.Id == key {
			Users = append(Users[:i], Users[i+1:]...)
		}
	}
}
func UpdateUser(w http.ResponseWriter, r *http.Request) {

	userId := mux.Vars(r)["id"]

	var updateUser User
	requestBody, err := ioutil.ReadAll(r.Body)

	if err != nil {
		fmt.Println("User couldn't add")
	}
	json.Unmarshal(requestBody, &updateUser)

	for i, selectedUser := range Users {
		if selectedUser.Id == userId {
			selectedUser.Id = updateUser.Id
			selectedUser.UserName = updateUser.UserName
			selectedUser.UserPwd = updateUser.UserPwd
			selectedUser.AuthorityId = updateUser.AuthorityId

			Users = append(Users[:i], selectedUser)

			json.NewEncoder(w).Encode(Users)
		}

	}
}

func handleRequest() {

	myRouter := mux.NewRouter().StrictSlash(true)
	myRouter.HandleFunc("/", homePage)
	myRouter.HandleFunc("/users", allUsers)
	myRouter.HandleFunc("/users", newUser).Methods("POST")
	myRouter.HandleFunc("/users/{id}", UpdateUser).Methods("PATCH")
	myRouter.HandleFunc("/users/{id}", deleteUser).Methods("DELETE")

	myRouter.HandleFunc("/users/{id}", getOneUser)
	log.Fatal(http.ListenAndServe(":8081", myRouter))
}

func Demo1() {
	Users = []User{

		User{"1", "Selcuk", "11234", 1},
		User{"2", "Selcuk2", "12434", 2},
		User{"3", "Selcuk1", "1234", 3},
		User{"4", "Selcuk3", "12324", 1},
		User{"5", "Selcuk5", "1234", 1},
	}

	handleRequest()

}
