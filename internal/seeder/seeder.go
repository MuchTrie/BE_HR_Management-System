package seeder

import (
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"securehr/backend/internal/model"
)

// These credentials are development fixtures only. Production credentials must
// be provisioned outside the repository and the seeder must not be enabled there.
const (
	adminEmail       = "admin@example.com"
	adminPassword    = "change-me-admin"
	managerEmail     = "manager@example.com"
	managerPassword  = "change-me-manager"
	employeeEmail    = "employee@example.com"
	employeePassword = "change-me-employee"
)

type account struct {
	email, password, role, number, firstName, lastName string
}

func Seed(db *gorm.DB) error {
	roles := make(map[string]model.Role, 3)
	for _, name := range []string{"ADMIN", "MANAGER", "EMPLOYEE"} {
		var role model.Role
		if err := db.Where("name = ?", name).FirstOrCreate(&role, model.Role{Name: name}).Error; err != nil {
			return fmt.Errorf("seed role %s: %w", name, err)
		}
		roles[name] = role
	}

	accounts := []account{
		{adminEmail, adminPassword, "ADMIN", "SEED-ADMIN", "Admin", "User"},
		{managerEmail, managerPassword, "MANAGER", "SEED-MANAGER", "Manager", "User"},
		{employeeEmail, employeePassword, "EMPLOYEE", "SEED-EMPLOYEE", "Employee", "User"},
	}
	employees := make(map[string]model.Employee, len(accounts))
	for _, fixture := range accounts {
		employee, err := ensureEmployee(db, fixture.number, fixture.email, fixture.firstName, fixture.lastName)
		if err != nil {
			return err
		}
		employees[fixture.role] = employee
		if err := ensureUser(db, fixture, employee, roles[fixture.role]); err != nil {
			return err
		}
	}
	admin := employees["ADMIN"]
	manager := employees["MANAGER"]
	employee := employees["EMPLOYEE"]

	departments := []model.Department{
		{Name: "Engineering", Description: "Product and software engineering team", ManagerID: &manager.ID},
		{Name: "Human Resources", Description: "People operations and employee support", ManagerID: &manager.ID},
		{Name: "Finance", Description: "Finance and accounting team"},
	}
	for _, department := range departments {
		if err := db.Where("name = ?", department.Name).FirstOrCreate(&department, department).Error; err != nil {
			return fmt.Errorf("seed department %s: %w", department.Name, err)
		}
	}

	positions := []model.Position{
		{Name: "Software Engineer", Description: "Builds and maintains application features", Level: 3},
		{Name: "Senior Software Engineer", Description: "Leads technical implementation", Level: 5},
		{Name: "HR Specialist", Description: "Supports HR operations", Level: 3},
		{Name: "Finance Specialist", Description: "Manages finance operations", Level: 3},
	}
	for _, position := range positions {
		if err := db.Where("name = ?", position.Name).FirstOrCreate(&position, position).Error; err != nil {
			return fmt.Errorf("seed position %s: %w", position.Name, err)
		}
	}

	var engineering, hr, finance model.Department
	var engineer, senior, hrSpecialist, financeSpecialist model.Position
	for _, target := range []struct {
		name string
		dest interface{}
	}{
		{"Engineering", &engineering}, {"Human Resources", &hr}, {"Finance", &finance},
	} {
		if err := db.Where("name = ?", target.name).First(target.dest).Error; err != nil {
			return fmt.Errorf("load seeded department %s: %w", target.name, err)
		}
	}
	for _, target := range []struct {
		name string
		dest interface{}
	}{
		{"Software Engineer", &engineer}, {"Senior Software Engineer", &senior},
		{"HR Specialist", &hrSpecialist}, {"Finance Specialist", &financeSpecialist},
	} {
		if err := db.Where("name = ?", target.name).First(target.dest).Error; err != nil {
			return fmt.Errorf("load seeded position %s: %w", target.name, err)
		}
	}

	if err := assignEmployee(db, &admin, &hr.ID, &hrSpecialist.ID, nil); err != nil {
		return err
	}
	if err := assignEmployee(db, &manager, &engineering.ID, &senior.ID, nil); err != nil {
		return err
	}
	if err := assignEmployee(db, &employee, &engineering.ID, &engineer.ID, &manager.ID); err != nil {
		return err
	}

	if err := seedAttendance(db, employee); err != nil {
		return err
	}
	if err := seedLeaves(db, employee, manager); err != nil {
		return err
	}
	return nil
}

func ensureEmployee(db *gorm.DB, number, email, firstName, lastName string) (model.Employee, error) {
	var employee model.Employee
	if err := db.Where("employee_number = ?", number).First(&employee).Error; err == nil {
		return employee, nil
	} else if err != gorm.ErrRecordNotFound {
		return employee, fmt.Errorf("find employee %s: %w", number, err)
	}
	employee = model.Employee{
		EmployeeNumber: number, FirstName: firstName, LastName: lastName,
		Email: email, JoinDate: time.Now().AddDate(-1, 0, 0), Status: "ACTIVE",
	}
	if err := db.Create(&employee).Error; err != nil {
		return employee, fmt.Errorf("create employee %s: %w", number, err)
	}
	return employee, nil
}

func ensureUser(db *gorm.DB, fixture account, employee model.Employee, role model.Role) error {
	var user model.User
	if err := db.Where("email = ?", fixture.email).First(&user).Error; err == nil {
		return nil
	} else if err != gorm.ErrRecordNotFound {
		return fmt.Errorf("find user %s: %w", fixture.email, err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(fixture.password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password for %s: %w", fixture.email, err)
	}
	user = model.User{EmployeeID: employee.ID, Email: fixture.email, PasswordHash: string(hash), RoleID: role.ID, IsActive: true}
	if err := db.Create(&user).Error; err != nil {
		return fmt.Errorf("create user %s: %w", fixture.email, err)
	}
	return nil
}

func assignEmployee(db *gorm.DB, employee *model.Employee, departmentID, positionID, managerID *uint) error {
	employee.DepartmentID, employee.PositionID, employee.ManagerID = departmentID, positionID, managerID
	if err := db.Model(employee).Updates(map[string]interface{}{
		"department_id": departmentID, "position_id": positionID, "manager_id": managerID,
	}).Error; err != nil {
		return fmt.Errorf("assign employee %s: %w", employee.EmployeeNumber, err)
	}
	return nil
}

func seedAttendance(db *gorm.DB, employee model.Employee) error {
	yesterday := dateOnly(time.Now().AddDate(0, 0, -1))
	today := dateOnly(time.Now())
	for _, date := range []time.Time{yesterday, today} {
		checkIn := date.Add(8*time.Hour + 30*time.Minute)
		checkOut := date.Add(17 * time.Hour)
		var attendance model.Attendance
		if err := db.Where("employee_id = ? AND date = ?", employee.ID, date).First(&attendance).Error; err == nil {
			continue
		} else if err != gorm.ErrRecordNotFound {
			return fmt.Errorf("find attendance: %w", err)
		}
		attendance = model.Attendance{EmployeeID: employee.ID, Date: date, CheckIn: &checkIn, CheckOut: &checkOut, Status: "PRESENT"}
		if err := db.Create(&attendance).Error; err != nil {
			return fmt.Errorf("create attendance: %w", err)
		}
	}
	return nil
}

func seedLeaves(db *gorm.DB, employee, manager model.Employee) error {
	start := dateOnly(time.Now().AddDate(0, 0, 7))
	end := start.AddDate(0, 0, 2)
	var pending int64
	db.Model(&model.LeaveRequest{}).Where("employee_id = ? AND status = ?", employee.ID, "PENDING").Count(&pending)
	if pending == 0 {
		request := model.LeaveRequest{EmployeeID: employee.ID, LeaveType: "ANNUAL", StartDate: start, EndDate: end, Reason: "Annual leave demo request", Status: "PENDING"}
		if err := db.Create(&request).Error; err != nil {
			return fmt.Errorf("create pending leave: %w", err)
		}
	}
	approvedStart := dateOnly(time.Now().AddDate(0, -1, 0))
	approvedEnd := approvedStart
	var approved int64
	db.Model(&model.LeaveRequest{}).Where("employee_id = ? AND status = ?", employee.ID, "APPROVED").Count(&approved)
	if approved == 0 {
		request := model.LeaveRequest{EmployeeID: employee.ID, LeaveType: "PERSONAL", StartDate: approvedStart, EndDate: approvedEnd, Reason: "Approved leave demo", Status: "APPROVED", ApprovedBy: &manager.ID}
		now := time.Now()
		request.ApprovedAt = &now
		if err := db.Create(&request).Error; err != nil {
			return fmt.Errorf("create approved leave: %w", err)
		}
	}
	return nil
}

func dateOnly(value time.Time) time.Time {
	return time.Date(value.Year(), value.Month(), value.Day(), 0, 0, 0, 0, value.Location())
}
