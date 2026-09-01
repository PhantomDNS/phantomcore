// SPDX-License-Identifier: GPL-3.0-or-later
package repositories

import (
	"testing"
	"time"

	"github.com/lopster568/phantomDNS/internal/storage/models"
)

func TestQueryLog_DeleteOlderThan(t *testing.T) {
	db := setupTestDB(t)
	repo := NewGormQueryLogRepo(db)

	now := time.Now()
	// 3 old (8 days), 2 recent (1 day).
	for i := 0; i < 3; i++ {
		db.Create(&models.DNSQuery{Domain: "old.com", Action: "allow", Timestamp: now.AddDate(0, 0, -8)})
	}
	for i := 0; i < 2; i++ {
		db.Create(&models.DNSQuery{Domain: "new.com", Action: "allow", Timestamp: now.AddDate(0, 0, -1)})
	}

	deleted, err := repo.DeleteOlderThan(now.AddDate(0, 0, -7))
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 3 {
		t.Errorf("deleted %d, want 3 (the 8-day-old rows)", deleted)
	}
	n, _ := repo.Count()
	if n != 2 {
		t.Errorf("remaining rows = %d, want 2", n)
	}
}

func TestQueryLog_DeleteOlderThan_Empty(t *testing.T) {
	db := setupTestDB(t)
	repo := NewGormQueryLogRepo(db)

	deleted, err := repo.DeleteOlderThan(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 0 {
		t.Errorf("deleted %d, want 0 on an empty table", deleted)
	}
}

func TestQueryLog_EnforceRowCap(t *testing.T) {
	db := setupTestDB(t)
	repo := NewGormQueryLogRepo(db)

	for i := 0; i < 10; i++ {
		db.Create(&models.DNSQuery{Domain: "x.com", Action: "allow", Timestamp: time.Now()})
	}

	deleted, err := repo.EnforceRowCap(4)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 6 {
		t.Errorf("deleted %d, want 6 (10 - cap of 4)", deleted)
	}
	n, _ := repo.Count()
	if n != 4 {
		t.Errorf("remaining rows = %d, want 4 (the cap)", n)
	}

	// The survivors must be the newest (highest ids).
	rows, _ := repo.ListRecent(10)
	if len(rows) != 4 {
		t.Fatalf("ListRecent returned %d rows, want 4", len(rows))
	}
	var minID uint = 1<<31 - 1
	for _, r := range rows {
		if r.ID < minID {
			minID = r.ID
		}
	}
	if minID != 7 { // ids 7,8,9,10 survive out of 1..10
		t.Errorf("lowest surviving id = %d, want 7 (kept the 4 newest)", minID)
	}
}

func TestQueryLog_EnforceRowCap_UnderCapNoop(t *testing.T) {
	db := setupTestDB(t)
	repo := NewGormQueryLogRepo(db)
	for i := 0; i < 3; i++ {
		db.Create(&models.DNSQuery{Domain: "x.com", Action: "allow", Timestamp: time.Now()})
	}
	deleted, err := repo.EnforceRowCap(100)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 0 {
		t.Errorf("deleted %d, want 0 (fewer rows than cap)", deleted)
	}
}

func TestQueryLog_EnforceRowCap_ZeroDisables(t *testing.T) {
	db := setupTestDB(t)
	repo := NewGormQueryLogRepo(db)
	for i := 0; i < 5; i++ {
		db.Create(&models.DNSQuery{Domain: "x.com", Action: "allow", Timestamp: time.Now()})
	}
	deleted, err := repo.EnforceRowCap(0)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 0 {
		t.Errorf("deleted %d, want 0 (maxRows=0 disables enforcement)", deleted)
	}
	n, _ := repo.Count()
	if n != 5 {
		t.Errorf("remaining rows = %d, want 5 (untouched)", n)
	}
}

func TestQueryLog_Count(t *testing.T) {
	db := setupTestDB(t)
	repo := NewGormQueryLogRepo(db)

	n, err := repo.Count()
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("Count() on empty table = %d, want 0", n)
	}

	db.Create(&models.DNSQuery{Domain: "x.com", Action: "allow", Timestamp: time.Now()})
	db.Create(&models.DNSQuery{Domain: "y.com", Action: "allow", Timestamp: time.Now()})

	n, err = repo.Count()
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("Count() = %d, want 2", n)
	}
}
