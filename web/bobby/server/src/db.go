package main

import (
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"os"
	"strings"
)

func createDBFilepath(file string) string {
	return "/server/db/" + file
}

func exist(file string) bool {
	_, err := os.Stat(createDBFilepath(file))
	return (err == nil)
}

func createDB(name string) {
	var splitted []string = strings.Split(name, "x")
	var fileName string

	if len(splitted) == 3 {
		fileName = splitted[0] + "x" + splitted[1] + ".db"
	}

	db, err := sql.Open("sqlite3", createDBFilepath(fileName))
	if err != nil {
		fmt.Println(err)
	}
	stmt, err := db.Prepare("CREATE TABLE USERS(user varchar(256), pass varchar(256))")
	if err != nil {
		fmt.Println(err)
	}

	stmt.Exec()
	stmt.Close()
	stmt, err = db.Prepare("INSERT INTO USERS(user, pass) values(?,?)")
	stmt.Exec(dbUser, dbPassword)

	if stmt != nil {
		stmt.Close()
	}
	if db != nil {
		db.Close()
	}
	if err != nil {
		fmt.Println(err)
	}
}

func login(id string, user string, pass string) bool {
	splitted := strings.Split(id, "x")
	var fileName string
	if len(splitted) == 3 {
		fileName = splitted[0] + "x" + splitted[1] + ".db"
	}

	if !exist(fileName) {
		fmt.Println("File doesnt exist!")
		fmt.Println(fileName)
		return false
	}
	db, err := sql.Open("sqlite3", createDBFilepath(fileName))
	if err != nil {
		fmt.Println(err)
		return false
	}
	defer db.Close()

	stmt, err := db.Prepare("SELECT user from USERS WHERE user=? AND pass=?")
	if err != nil {
		fmt.Println(err)
		return false
	}
	defer stmt.Close()

	result, err := stmt.Query(user, pass)
	var userName string
	if result.Next() {
		err = result.Scan(&userName)
	}
	if (err == nil) && (len(userName) > 0) {
		return true
	}
	if err != nil {
		fmt.Println(err)
	}
	return false
}

func changePassword(id string, user string, oldPass string, newPass string) string {
	var splitted []string = strings.Split(id, "x")
	var fileName string
	if len(splitted) == 3 {
		fileName = splitted[0] + "x" + splitted[1] + ".db"
	}
	if !exist(fileName) {
		return ""
	}
	db, err := sql.Open("sqlite3", createDBFilepath(fileName))
	if err != nil {
		fmt.Println(err)
		return err.Error()
	}
	defer db.Close()

	stmt, err := db.Prepare(fmt.Sprintf(`UPDATE USERS SET pass='%s' WHERE user=? AND pass=?`, newPass))
	if err != nil {
		fmt.Println(err)
		return err.Error()
	}
	defer stmt.Close()

	res, err := stmt.Exec(user, oldPass)
	if err != nil {
		fmt.Println(err)
		return err.Error()
	}
	affected, err := res.RowsAffected()
	if err != nil {
		fmt.Println(err)
		return err.Error()
	}

	if affected > 0 {
		return "Password changed!"
	}
	return "Failed to change password!"
}
