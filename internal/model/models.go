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
	ID              uint       `gorm:"primaryKey" json:"id"`
	EmployeeID      uint       `gorm:"not null" json:"employee_id"`
	LeaveType       string     `gorm:"size:30;not null" json:"leave_type"`
	StartDate       time.Time  `gorm:"type:date;not null" json:"start_date"`
	EndDate         time.Time  `gorm:"type:date;not null" json:"end_date"`
	Reason          string     `gorm:"type:text;not null" json:"reason"`
	Status          string     `gorm:"size:20;not null;default:PENDING" json:"status"`
	ApprovedBy      *uint      `json:"approved_by"`
	ApprovedAt      *time.Time `json:"approved_at"`
	RejectionReason string     `gorm:"type:text" json:"rejection_reason,omitempty"`
	CancelledAt     *time.Time `json:"cancelled_at,omitempty"`
	ApprovalLevel   int        `gorm:"not null;default:0" json:"approval_level"`
	RequiredLevels  int        `gorm:"not null;default:1" json:"required_levels"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	Employee        Employee   `json:"employee"`
	Approver        *User      `gorm:"foreignKey:ApprovedBy" json:"approver,omitempty"`
}

type LeavePolicy struct {
	ID                     uint      `gorm:"primaryKey" json:"id"`
	LeaveType              string    `gorm:"uniqueIndex;size:30;not null" json:"leave_type"`
	AnnualQuotaDays        int       `gorm:"not null" json:"annual_quota_days"`
	MaxConsecutiveDays     int       `gorm:"not null;default:0" json:"max_consecutive_days"`
	AllowWeekend           bool      `gorm:"not null;default:false" json:"allow_weekend"`
	RequiredApprovalLevels int       `gorm:"not null;default:1" json:"required_approval_levels"`
	CreatedAt              time.Time `json:"created_at"`
	UpdatedAt              time.Time `json:"updated_at"`
}

type LeaveBalance struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	EmployeeID   uint      `gorm:"uniqueIndex:uq_leave_balance;not null" json:"employee_id"`
	LeaveType    string    `gorm:"uniqueIndex:uq_leave_balance;size:30;not null" json:"leave_type"`
	Year         int       `gorm:"uniqueIndex:uq_leave_balance;not null" json:"year"`
	EntitledDays int       `gorm:"not null" json:"entitled_days"`
	AdjustedDays int       `gorm:"not null;default:0" json:"adjusted_days"`
	UsedDays     int       `gorm:"not null;default:0" json:"used_days"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type CompanyHoliday struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Date      time.Time `gorm:"uniqueIndex;type:date;not null" json:"date"`
	Name      string    `gorm:"size:150;not null" json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type LeaveStatusHistory struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	LeaveID    uint      `gorm:"index;not null" json:"leave_id"`
	FromStatus string    `gorm:"size:20" json:"from_status"`
	ToStatus   string    `gorm:"size:20;not null" json:"to_status"`
	ChangedBy  uint      `gorm:"not null" json:"changed_by"`
	Reason     string    `gorm:"type:text" json:"reason,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

type ApprovalDelegation struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	ManagerID  uint      `gorm:"index;not null" json:"manager_id"`
	DelegateID uint      `gorm:"index;not null" json:"delegate_id"`
	StartDate  time.Time `gorm:"type:date;not null" json:"start_date"`
	EndDate    time.Time `gorm:"type:date;not null" json:"end_date"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type RefreshToken struct {
	ID        uint      `gorm:"primaryKey"`
	UserID    uint      `gorm:"not null;index"`
	TokenHash string    `gorm:"uniqueIndex;size:64;not null"`
	ExpiresAt time.Time `gorm:"not null;index"`
	RevokedAt *time.Time
	CreatedAt time.Time
}
