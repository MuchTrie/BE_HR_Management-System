package server

import (
	"fmt"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"securehr/backend/internal/model"
)

func newLeaveRulesTestServer(t *testing.T) *Server {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:leave_rules_%s?mode=memory&cache=shared", t.Name())), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&model.LeavePolicy{}, &model.LeaveRequest{}, &model.CompanyHoliday{}); err != nil {
		t.Fatal(err)
	}
	return &Server{db: db}
}

func TestValidateLeaveDatesRejectsWeekendAndHoliday(t *testing.T) {
	server := newLeaveRulesTestServer(t)
	policy := model.LeavePolicy{LeaveType: "ANNUAL", AnnualQuotaDays: 12, MaxConsecutiveDays: 12}
	if _, valid, _ := server.validateLeaveDates(time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC), time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC), policy); valid {
		t.Fatal("expected weekend leave to be rejected")
	}

	if err := server.db.Create(&model.CompanyHoliday{Date: time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC), Name: "Holiday"}).Error; err != nil {
		t.Fatal(err)
	}
	if _, valid, _ := server.validateLeaveDates(time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC), time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC), policy); valid {
		t.Fatal("expected company holiday leave to be rejected")
	}
}

func TestHasLeaveBalanceReservesPendingAndApprovedLeave(t *testing.T) {
	server := newLeaveRulesTestServer(t)
	if err := server.db.Create(&model.LeavePolicy{LeaveType: "ANNUAL", AnnualQuotaDays: 5}).Error; err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	if err := server.db.Create(&model.LeaveRequest{
		EmployeeID: 7, LeaveType: "ANNUAL", StartDate: start, EndDate: start.AddDate(0, 0, 2), Status: "PENDING",
	}).Error; err != nil {
		t.Fatal(err)
	}
	if server.hasLeaveBalance(7, "ANNUAL", 2026, 3, 0) {
		t.Fatal("expected pending days to reserve quota")
	}
	if !server.hasLeaveBalance(7, "ANNUAL", 2026, 2, 0) {
		t.Fatal("expected request within remaining quota to pass")
	}
}
