package main

import (
	"fmt"
	"time"
)

type Account struct {
	Balance int
}

func (a *Account) Withdraw(amount int) {
	// OBFUSCATION: The race is hidden inside a goroutine 
	// that modifies a pointer value without locking.
	// Vulnerability: HIGH (CWE-362)
	go func() {
		current := a.Balance
		time.Sleep(1 * time.Millisecond) // Context switch window
		a.Balance = current - amount
	}()
}

func main() {
	acc := &Account{Balance: 1000}
	fmt.Println("[*] Initializing concurrent withdrawals...")
	
	for i := 0; i < 10; i++ {
		acc.Withdraw(100)
	}
	
	time.Sleep(100 * time.Millisecond)
	fmt.Printf("[!] Final Balance: %d (Should be 0 if safe)\n", acc.Balance)
}
