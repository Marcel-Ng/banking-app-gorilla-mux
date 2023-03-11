package main

import (
	"math/rand"
	"time"
)

type TransferRequest struct {
	ToAccount int `json:"to_account"`
	Amount    int `json:"amount"`
}

type CreateAccountRequest struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	// Number    int64  `json:"number"`
	// Balance   int64  `json:"balance"`
}

type Account struct {
	ID        int       `json:"id"`
	FistName  string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	Number    int64     `json:"number"`
	Balance   int64     `json:"balance"`
	CreatedAt time.Time `json:"createdAt"`
}

func NewAccount(firstName, lastName string) *Account {
	return &Account{
		// ID:        rand.Intn(1000),
		FistName:  firstName,
		LastName:  lastName,
		Number:    int64(rand.Intn(100000)),
		Balance:   0,
		CreatedAt: time.Now().UTC(),
	}
}
