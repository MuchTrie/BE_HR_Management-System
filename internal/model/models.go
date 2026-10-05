package model

import "time"

type Role struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Name      string    `gorm:"uniqueIndex;size:20;not null" json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Employee struct {
	ID             uint        `gorm:"primaryKey" json:"id"`
	EmployeeNumber string      `gorm:"uniqueIndex;size:30;not null" json:"employee_number"`
	FirstName      string      `gorm:"size:100;not null" json:"first_name"`
	LastName       string      `gorm:"size:100" json:"last_name"`
	Email          string      `gorm:"uniqueIndex;size:255;not null" json:"email"`
	Phone          string      `gorm:"size:30" json:"phone"`
	Address        string      `gorm:"type:text" json:"address"`
	DateOfBirth    *time.Time  `json:"date_of_birth"`
	Gender         string      `gorm:"size:20" json:"gender"`
	DepartmentID   *uint       `json:"department_id"`
	PositionID     *uint       `json:"position_id"`
	ManagerID      *uint       `json:"manager_id"`
	JoinDate       time.Time   `gorm:"not null" json:"join_date"`
	Status         string      `gorm:"size:20;not null;default:ACTIVE" json:"status"`
	CreatedAt      time.Time   `json:"created_at"`
	UpdatedAt      time.Time   `json:"updated_at"`
	DeletedAt      *time.Time  `gorm:"index" json:"-"`
	Department     *Department `gorm:"foreignKey:DepartmentID" json:"department,omitempty"`
	Position       *Position   `gorm:"foreignKey:PositionID" json:"position,omitempty"`
	Manager        *Employee   `gorm:"foreignKey:ManagerID" json:"manager,omitempty"`
}

type User struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	EmployeeID   uint      `gorm:"uniqueIndex;not null" json:"employee_id"`
	Email        string    `gorm:"uniqueIndex;size:255;not null" json:"email"`
	PasswordHash string    `gorm:"size:255;not null" json:"-"`
	RoleID       uint      `gorm:"not null" json:"role_id"`
	IsActive     bool      `gorm:"not null;default:true" json:"is_active"`
	Employee     Employee  `json:"employee"`
	Role         Role      `json:"role"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type Department struct {
	ID            uint       `gorm:"primaryKey" json:"id"`
	Name          string     `gorm:"uniqueIndex;size:100;not null" json:"name"`
	Description   string     `gorm:"type:text" json:"description"`
	ManagerID     *uint      `json:"manager_id"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	DeletedAt     *time.Time `gorm:"index" json:"-"`
	Manager       *Employee  `gorm:"foreignKey:ManagerID" json:"manager,omitempty"`
	EmployeeCount int        `gorm:"-" json:"employee_count"`
}

type Position struct {
	ID          uint       `gorm:"primaryKey" json:"id"`
	Name        string     `gorm:"uniqueIndex;size:100;not null" json:"name"`
	Description string     `gorm:"type:text" json:"description"`
	Level       int        `json:"level"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	DeletedAt   *time.Time `gorm:"index" json:"-"`
}

type Attendance struct {
	ID         uint       `gorm:"primaryKey" json:"id"`
	EmployeeID uint       `gorm:"not null;uniqueIndex:uq_attendance_day" json:"employee_id"`
	Date       time.Time  `gorm:"type:date;not null;uniqueIndex:uq_attendance_day" json:"date"`
	CheckIn    *time.Time `json:"check_in"`
	CheckOut   *time.Time `json:"check_out"`
	Status     string     `gorm:"size:20;not null" json:"status"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	Employee   Employee   `json:"employee"`
}

type LeaveRequest struct {
	ID         uint       `gorm:"primaryKey" json:"id"`
	EmployeeID uint       `gorm:"not null" json:"employee_id"`
	LeaveType  string     `gorm:"size:30;not null" json:"leave_type"`
	StartDate  time.Time  `gorm:"type:date;not null" json:"start_date"`
	EndDate    time.Time  `gorm:"type:date;not null" json:"end_date"`
	Reason     string     `gorm:"type:text;not null" json:"reason"`
	Status     string     `gorm:"size:20;not null;default:PENDING" json:"status"`
	ApprovedBy *uint      `json:"approved_by"`
	ApprovedAt *time.Time `json:"approved_at"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	Employee   Employee   `json:"employee"`
}

type RefreshToken struct {
	ID        uint      `gorm:"primaryKey"`
	UserID    uint      `gorm:"not null;index"`
	TokenHash string    `gorm:"uniqueIndex;size:64;not null"`
	ExpiresAt time.Time `gorm:"not null;index"`
	RevokedAt *time.Time
	CreatedAt time.Time
}
