package models

import "time"

type DNSQuery struct {
	ID        uint      `gorm:"primaryKey"`
	Domain    string    `gorm:"index;not null;"`
	ClientIP  string    `gorm:"index;not null;"`
	Action    string    `gorm:"not null;"` //allow, block, log
	Timestamp time.Time `gorm:"index;"`
}
