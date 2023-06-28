package getpost

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type Users struct {
	Id          int    `json:"id"`
	UserName    string `json:"userName"`
	UserPwd     string `json:"userPwd"`
	AuthorityId int    `json:"authorityId"`
}
type Authority struct {
	Id            int `json:"id"`
	AuthorityName int `json:"authorityName"`
}

func UserPost() {
	users := Users{4, "mehmet", "1234", 1}
	jsonUsers, _ := json.Marshal(users)
	response, err := http.Post("http://localhost:3000/users", "application/json;charset=utf-8", bytes.NewBuffer(jsonUsers))

	if err != nil {
		fmt.Println("An Error Occured")
	}
	defer response.Body.Close()

}

func UserGet() {
	response, err := http.Get("http://localhost:3000/users")

	if err != nil {
		fmt.Println("An Error Occured")
	}

	defer response.Body.Close()

	bodyByte, _ := ioutil.ReadAll(response.Body)

	var usersGet []Users
	json.Unmarshal(bodyByte, &usersGet)
	fmt.Println(usersGet)

}

/*func UserDelete() {
	client := &http.Client{}
	resquest, err := http.NewRequest("DELETE", "http://localhost:3000/users/1", nil)
	if err != nil {
		fmt.Println(err)
	}
	defer resquest.Body.Close()

	response, err := client.Do(resquest)

	if err != nil {
		fmt.Println(err)
	}
	defer response.Body.Close()

	fmt.Println("User Deleted")

}*/
