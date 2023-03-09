package main

import "math/rand"

type Account struct {
	ID       int    `json:"id"`
	FistName string `json:"first_name"`
	LastName string `json:"last_name"`
	Number   int64  `json:"number"`
	Balance  int64  `json:"balance"`
}

func NewAccount(firstName, lastName string) *Account {
	return &Account{
		ID:       rand.Intn(1000),
		FistName: firstName,
		LastName: lastName,
		Number:   int64(rand.Intn(100000)),
		Balance:  0,
	}
}
