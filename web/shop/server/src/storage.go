package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
)

const MAX_DEBT int64 = 200
const START_BALANCE int64 = 100
const START_DEBT int64 = 0

var mutex sync.Mutex

type BankAccount struct {
	balance int64
	debt    int64
}

var accounts = make(map[string]BankAccount)

func borrow(key string, sum int64) (ok bool) {
	mutex.Lock()
	var account BankAccount
	account, ok = accounts[key]
	if ok {
		ok = false
		newDebt := account.debt + sum
		newBalance := account.balance + sum
		if (newDebt <= MAX_DEBT) && (newDebt >= 0) && (newBalance >= 0) && (sum >= 0) {
			ok = true
			account.debt = newDebt
			account.balance = newBalance
			accounts[key] = account
		}
	}
	mutex.Unlock()
	return
}

func repay(key string, sum int64) (ok bool) {
	mutex.Lock()
	var account BankAccount
	account, ok = accounts[key]
	if ok {
		ok = false
		newDebt := account.debt - sum
		newBalance := account.balance - sum
		if (newDebt >= 0) && (newBalance >= 0) && (sum >= 0) {
			ok = true
			account.debt = newDebt
			account.balance = newBalance
			accounts[key] = account
		}
	}
	mutex.Unlock()
	return
}

func buy(key string, sum int64) (ok bool) {
	mutex.Lock()
	var account BankAccount
	account, ok = accounts[key]
	if ok {
		ok = false
		newBalance := account.balance - sum
		if newBalance >= 0 {
			ok = true
			account.balance = newBalance
			accounts[key] = account
		}
	}
	mutex.Unlock()
	return
}

func bankStatement(key string) string {
	mutex.Lock()
	account, ok := accounts[key]
	mutex.Unlock()
	if ok {
		return fmt.Sprintf(`<table><tr><td>Balance</td><td>%d$</td></tr><tr><td>Debt</td><td>%d$</td></tr></table>`, account.balance, account.debt)
	}
	return ""
}

func validate(key string) bool {
	mutex.Lock()
	_, ok := accounts[key]
	mutex.Unlock()
	return ok
}

func create() (key string) {
	keyBytes := make([]byte, 32)
	rand.Read(keyBytes)
	key = hex.EncodeToString(keyBytes)

	mutex.Lock()
	var account BankAccount
	account.balance = START_BALANCE
	account.debt = START_DEBT
	accounts[key] = account
	mutex.Unlock()
	return
}
