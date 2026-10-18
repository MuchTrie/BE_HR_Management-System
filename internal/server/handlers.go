package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"securehr/backend/internal/model"
)

func ok(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, gin.H{"success": true, "data": data})
}
func created(c *gin.Context, data interface{}) {
	c.JSON(http.StatusCreated, gin.H{"success": true, "data": data})
}
func fail(c *gin.Context, status int, code, message string) {
	c.JSON(status, gin.H{"success": false, "error": gin.H{"code": code, "message": message}})
}
func id(c *gin.Context) (uint, bool) {
	var value uint
	_, err := fmt.Sscan(c.Param("id"), &value)
	return value, err == nil && value > 0
}

func (s *Server) login(c *gin.Context) {
	var input struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=8"`
	}
	if c.ShouldBindJSON(&input) != nil {
		fail(c, 400, "INVALID_REQUEST", "Email and password are required")
		return
	}
	var user model.User
	if s.db.Preload("Role").Preload("Employee").Where("email = ? AND is_active = ?", strings.ToLower(input.Email), true).First(&user).Error != nil || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(input.Password)) != nil {
		fail(c, 401, "INVALID_CREDENTIALS", "Email or password is incorrect")
		return
	}
	access, err := s.accessToken(user)
	if err != nil {
		fail(c, 500, "TOKEN_ERROR", "Could not create access token")
		return
	}
	refresh, err := s.refreshToken(user.ID)
	if err != nil {
		fail(c, 500, "TOKEN_ERROR", "Could not create refresh token")
		return
	}
	ok(c, gin.H{"token": access, "refresh_token": refresh, "user": publicUser(user)})
}

func (s *Server) accessToken(user model.User) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": user.ID, "role": user.Role.Name, "exp": time.Now().Add(time.Duration(s.cfg.AccessTokenMinutes) * time.Minute).Unix(), "iat": time.Now().Unix()}).SignedString([]byte(s.cfg.JWTSecret))
}
func hashToken(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
func (s *Server) refreshToken(userID uint) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw)
	expires := time.Now().Add(time.Duration(s.cfg.RefreshTokenDays) * 24 * time.Hour)
	if err := s.db.Create(&model.RefreshToken{UserID: userID, TokenHash: hashToken(token), ExpiresAt: expires}).Error; err != nil {
		return "", err
	}
	return token, nil
}

func (s *Server) refresh(c *gin.Context) {
	var input struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}
	if c.ShouldBindJSON(&input) != nil {
		fail(c, 400, "INVALID_REQUEST", "refresh_token is required")
		return
	}
	var stored model.RefreshToken
	if s.db.Where("token_hash = ? AND revoked_at IS NULL AND expires_at > ?", hashToken(input.RefreshToken), time.Now()).First(&stored).Error != nil {
		fail(c, 401, "INVALID_REFRESH_TOKEN", "Refresh token is invalid or expired")
		return
	}
	var user model.User
	if s.db.Preload("Role").Preload("Employee").First(&user, stored.UserID).Error != nil || !user.IsActive {
		fail(c, 401, "UNAUTHORIZED", "User is inactive")
		return
	}
	now := time.Now()
	s.db.Model(&stored).Update("revoked_at", now)
	access, err := s.accessToken(user)
	if err != nil {
		fail(c, 500, "TOKEN_ERROR", "Could not create access token")
		return
	}
	next, err := s.refreshToken(user.ID)
	if err != nil {
		fail(c, 500, "TOKEN_ERROR", "Could not create refresh token")
		return
	}
	ok(c, gin.H{"token": access, "refresh_token": next, "user": publicUser(user)})
}
func (s *Server) logout(c *gin.Context) {
	var input struct {
		RefreshToken string `json:"refresh_token"`
	}
	_ = c.ShouldBindJSON(&input)
	if input.RefreshToken != "" {
		s.db.Model(&model.RefreshToken{}).Where("token_hash = ? AND revoked_at IS NULL", hashToken(input.RefreshToken)).Update("revoked_at", time.Now())
	}
	ok(c, gin.H{"logged_out": true})
}
func (s *Server) me(c *gin.Context) {
	var user model.User
	uid := c.MustGet("user_id")
	if s.db.Preload("Role").Preload("Employee").First(&user, uid).Error != nil {
		fail(c, 404, "NOT_FOUND", "User not found")
		return
	}
	ok(c, publicUser(user))
}
func publicUser(user model.User) gin.H {
	return gin.H{"id": user.ID, "email": user.Email, "role": user.Role.Name, "employee_id": user.EmployeeID, "employee": user.Employee}
}

func (s *Server) listEmployees(c *gin.Context) {
	var employees []model.Employee
	q := s.db.Preload("Department").Preload("Position").Where("status <> ?", "RESIGNED")
	if role, _ := c.Get("role"); role == "MANAGER" {
		q = q.Where("manager_id = ?", s.currentEmployee(c))
	}
	if search := c.Query("search"); search != "" {
		like := "%" + search + "%"
		q = q.Where("first_name LIKE ? OR last_name LIKE ? OR email LIKE ? OR employee_number LIKE ?", like, like, like, like)
	}
	if departmentID := c.Query("department_id"); departmentID != "" {
		q = q.Where("department_id = ?", departmentID)
	}
	if status := c.Query("status"); status != "" {
		q = q.Where("status = ?", status)
	}

	q.Find(&employees)
	ok(c, gin.H{"items": employees, "total": len(employees), "page": 1, "per_page": len(employees), "total_pages": 1})
}

func (s *Server) listUsers(c *gin.Context) {
	var users []model.User
	s.db.Preload("Role").Preload("Employee").Find(&users)
	ok(c, users)
}

func (s *Server) toggleUserStatus(c *gin.Context) {
	userID, valid := id(c)
	if !valid {
		fail(c, http.StatusBadRequest, "INVALID_ID", "Invalid user id")
		return
	}
	var user model.User
	if s.db.First(&user, userID).Error != nil {
		fail(c, http.StatusNotFound, "NOT_FOUND", "User not found")
		return
	}
	user.IsActive = !user.IsActive
	if s.db.Save(&user).Error != nil {
		fail(c, http.StatusInternalServerError, "UPDATE_FAILED", "Could not update user")
		return
	}
	s.db.Preload("Role").Preload("Employee").First(&user, userID)
	ok(c, user)
}
func (s *Server) getEmployee(c *gin.Context) {
	employeeID, valid := id(c)
	if !valid {
		fail(c, 400, "INVALID_ID", "Invalid employee id")
		return
	}
	var employee model.Employee
	if s.db.First(&employee, employeeID).Error != nil {
		fail(c, 404, "NOT_FOUND", "Employee not found")
		return
	}
	ok(c, employee)
}
func (s *Server) createEmployee(c *gin.Context) {
	var employee model.Employee
	if c.ShouldBindJSON(&employee) != nil {
		fail(c, 400, "INVALID_REQUEST", "Invalid employee payload")
		return
	}
	if err := s.db.Create(&employee).Error; err != nil {
		fail(c, 409, "DUPLICATE", "Employee number or email already exists")
		return
	}
	created(c, employee)
}
func (s *Server) updateEmployee(c *gin.Context) {
	employeeID, valid := id(c)
	if !valid {
		fail(c, 400, "INVALID_ID", "Invalid employee id")
		return
	}
	var employee model.Employee
	if s.db.First(&employee, employeeID).Error != nil {
		fail(c, 404, "NOT_FOUND", "Employee not found")
		return
	}
	var input model.Employee
	if c.ShouldBindJSON(&input) != nil {
		fail(c, 400, "INVALID_REQUEST", "Invalid employee payload")
		return
	}
	input.ID = employee.ID
	if err := s.db.Model(&employee).Updates(input).Error; err != nil {
		fail(c, 409, "UPDATE_FAILED", "Could not update employee")
		return
	}
	s.db.First(&employee, employeeID)
	ok(c, employee)
}
func (s *Server) deleteEmployee(c *gin.Context) {
	employeeID, valid := id(c)
	if !valid {
		fail(c, 400, "INVALID_ID", "Invalid employee id")
		return
	}
	if s.db.Model(&model.Employee{}).Where("id = ?", employeeID).Update("status", "INACTIVE").RowsAffected == 0 {
		fail(c, 404, "NOT_FOUND", "Employee not found")
		return
	}
	ok(c, gin.H{"id": employeeID, "status": "INACTIVE"})
}

func (s *Server) listDepartments(c *gin.Context) {
	var values []model.Department
	s.db.Preload("Manager").Find(&values)
	for index := range values {
		var count int64
		s.db.Model(&model.Employee{}).Where("department_id = ? AND status = ?", values[index].ID, "ACTIVE").Count(&count)
		values[index].EmployeeCount = int(count)
	}
	ok(c, values)
}
func (s *Server) getDepartment(c *gin.Context) {
	var value model.Department
	if !bindExisting(s.db, c, &value) {
		return
	}
	ok(c, value)
}
func (s *Server) createDepartment(c *gin.Context) {
	var value model.Department
	if c.ShouldBindJSON(&value) != nil {
		fail(c, 400, "INVALID_REQUEST", "Invalid department payload")
		return
	}
	if s.db.Create(&value).Error != nil {
		fail(c, 409, "DUPLICATE", "Department already exists")
		return
	}
	created(c, value)
}
func (s *Server) updateDepartment(c *gin.Context) {
	var value model.Department
	if !bindExisting(s.db, c, &value) {
		return
	}
	if c.ShouldBindJSON(&value) != nil {
		fail(c, 400, "INVALID_REQUEST", "Invalid department payload")
		return
	}
	s.db.Save(&value)
	ok(c, value)
}
func (s *Server) deleteDepartment(c *gin.Context) { softDelete(s.db, c, &model.Department{}) }
func (s *Server) listPositions(c *gin.Context) {
	var values []model.Position
	s.db.Find(&values)
	ok(c, values)
}
func (s *Server) getPosition(c *gin.Context) {
	var value model.Position
	if !bindExisting(s.db, c, &value) {
		return
	}
	ok(c, value)
}
func (s *Server) createPosition(c *gin.Context) {
	var value model.Position
	if c.ShouldBindJSON(&value) != nil {
		fail(c, 400, "INVALID_REQUEST", "Invalid position payload")
		return
	}
	if s.db.Create(&value).Error != nil {
		fail(c, 409, "DUPLICATE", "Position already exists")
		return
	}
	created(c, value)
}
func (s *Server) updatePosition(c *gin.Context) {
	var value model.Position
	if !bindExisting(s.db, c, &value) {
		return
	}
	if c.ShouldBindJSON(&value) != nil {
		fail(c, 400, "INVALID_REQUEST", "Invalid position payload")
		return
	}
	s.db.Save(&value)
	ok(c, value)
}
func (s *Server) deletePosition(c *gin.Context) { softDelete(s.db, c, &model.Position{}) }
func bindExisting(db *gorm.DB, c *gin.Context, destination interface{}) bool {
	value, valid := id(c)
	if !valid {
		fail(c, 400, "INVALID_ID", "Invalid id")
		return false
	}
	if db.First(destination, value).Error != nil {
		fail(c, 404, "NOT_FOUND", "Record not found")
		return false
	}
	return true
}
func softDelete(db *gorm.DB, c *gin.Context, destination interface{}) {
	value, valid := id(c)
	if !valid {
		fail(c, 400, "INVALID_ID", "Invalid id")
		return
	}
	if db.Delete(destination, value).RowsAffected == 0 {
		fail(c, 404, "NOT_FOUND", "Record not found")
		return
	}
	ok(c, gin.H{"id": value, "deleted": true})
}

func (s *Server) checkIn(c *gin.Context) {
	employeeID := s.currentEmployee(c)
	if employeeID == 0 {
		return
	}
	today := time.Now().Truncate(24 * time.Hour)
	var attendance model.Attendance
	if s.db.Where("employee_id = ? AND date = ?", employeeID, today).First(&attendance).Error == nil {
		fail(c, 409, "ALREADY_CHECKED_IN", "Employee already checked in today")
		return
	}
	now := time.Now()
	status := "PRESENT"
	if now.Hour() >= 9 {
		status = "LATE"
	}
	attendance = model.Attendance{EmployeeID: employeeID, Date: today, CheckIn: &now, Status: status}
	if s.db.Create(&attendance).Error != nil {
		fail(c, 409, "CHECK_IN_FAILED", "Could not check in")
		return
	}
	created(c, attendance)
}
func (s *Server) checkOut(c *gin.Context) {
	employeeID := s.currentEmployee(c)
	if employeeID == 0 {
		return
	}
	var attendance model.Attendance
	if s.db.Where("employee_id = ? AND date = ?", employeeID, time.Now().Truncate(24*time.Hour)).First(&attendance).Error != nil || attendance.CheckIn == nil {
		fail(c, 409, "NOT_CHECKED_IN", "Employee has not checked in today")
		return
	}
	if attendance.CheckOut != nil {
		fail(c, 409, "ALREADY_CHECKED_OUT", "Employee already checked out today")
		return
	}
	now := time.Now()
	s.db.Model(&attendance).Update("check_out", &now)
	attendance.CheckOut = &now
	ok(c, attendance)
}
func (s *Server) currentEmployee(c *gin.Context) uint {
	var user model.User
	if s.db.First(&user, c.MustGet("user_id")).Error != nil {
		fail(c, 401, "UNAUTHORIZED", "User not found")
		return 0
	}
	return user.EmployeeID
}
func (s *Server) listAttendance(c *gin.Context) {
	var values []model.Attendance
	q := s.db.Preload("Employee")
	if role, _ := c.Get("role"); role == "MANAGER" {
		q = q.Where("employee_id IN (?)", s.db.Model(&model.Employee{}).Select("id").Where("manager_id = ?", s.currentEmployee(c)))
	}
	if employeeID := c.Query("employee_id"); employeeID != "" {
		q = q.Where("employee_id = ?", employeeID)
	}
	if dateFrom := c.Query("date_from"); dateFrom != "" {
		q = q.Where("date >= ?", dateFrom)
	}
	if dateTo := c.Query("date_to"); dateTo != "" {
		q = q.Where("date <= ?", dateTo)
	}
	q.Order("date DESC").Find(&values)
	ok(c, values)
}

func (s *Server) createLeave(c *gin.Context) {
	employeeID := s.currentEmployee(c)
	if employeeID == 0 {
		return
	}
	var input struct {
		LeaveType string `json:"leave_type" binding:"required"`
		StartDate string `json:"start_date" binding:"required"`
		EndDate   string `json:"end_date" binding:"required"`
		Reason    string `json:"reason" binding:"required"`
	}
	if c.ShouldBindJSON(&input) != nil {
		fail(c, 400, "INVALID_REQUEST", "Invalid leave dates or payload")
		return
	}
	startDate, err := parseDate(input.StartDate)
	if err != nil {
		fail(c, 400, "INVALID_REQUEST", "Dates must use YYYY-MM-DD format")
		return
	}
	endDate, err := parseDate(input.EndDate)
	if err != nil || endDate.Before(startDate) {
		fail(c, 400, "INVALID_REQUEST", "Invalid leave dates or payload")
		return
	}
	var overlap int64
	s.db.Model(&model.LeaveRequest{}).Where("employee_id = ? AND status IN ? AND start_date <= ? AND end_date >= ?", employeeID, []string{"PENDING", "APPROVED"}, endDate, startDate).Count(&overlap)
	if overlap > 0 {
		fail(c, 409, "LEAVE_OVERLAP", "Leave dates overlap an existing request")
		return
	}
	value := model.LeaveRequest{EmployeeID: employeeID, LeaveType: input.LeaveType, StartDate: startDate, EndDate: endDate, Reason: input.Reason, Status: "PENDING"}
	if s.db.Create(&value).Error != nil {
		fail(c, 500, "CREATE_FAILED", "Could not create leave request")
		return
	}
	s.db.Preload("Employee").First(&value, value.ID)
	created(c, value)
}
func (s *Server) listLeaves(c *gin.Context) {
	var values []model.LeaveRequest
	q := s.db.Preload("Employee").Preload("Approver").Preload("Approver.Employee")
	role, _ := c.Get("role")
	if role == "EMPLOYEE" {
		q = q.Where("employee_id = ?", s.currentEmployee(c))
	} else if role == "MANAGER" {
		q = q.Where("employee_id IN (?)", s.db.Model(&model.Employee{}).Select("id").Where("manager_id = ?", s.currentEmployee(c)))
	}
	if status := c.Query("status"); status != "" {
		q = q.Where("status = ?", status)
	}
	if employeeID := c.Query("employee_id"); employeeID != "" && role == "ADMIN" {
		q = q.Where("employee_id = ?", employeeID)
	}
	q.Order("created_at DESC").Find(&values)
	ok(c, values)
}
func (s *Server) getLeave(c *gin.Context) {
	leaveID, valid := id(c)
	if !valid {
		fail(c, 400, "INVALID_ID", "Invalid leave id")
		return
	}
	var value model.LeaveRequest
	if s.db.Preload("Employee").Preload("Approver").Preload("Approver.Employee").First(&value, leaveID).Error != nil {
		fail(c, 404, "NOT_FOUND", "Leave request not found")
		return
	}
	if !s.canAccessLeave(c, value) {
		fail(c, 403, "FORBIDDEN", "You cannot access this leave request")
		return
	}
	ok(c, value)
}
func (s *Server) approveLeave(c *gin.Context) { s.changeLeaveStatus(c, "APPROVED") }
func (s *Server) rejectLeave(c *gin.Context)  { s.changeLeaveStatus(c, "REJECTED") }
func (s *Server) cancelLeave(c *gin.Context)  { s.changeLeaveStatus(c, "CANCELLED") }
func (s *Server) changeLeaveStatus(c *gin.Context, status string) {
	leaveID, valid := id(c)
	if !valid {
		fail(c, 400, "INVALID_ID", "Invalid leave id")
		return
	}
	var value model.LeaveRequest
	if s.db.First(&value, leaveID).Error != nil {
		fail(c, 404, "NOT_FOUND", "Leave request not found")
		return
	}
	if !s.canAccessLeave(c, value) {
		fail(c, 403, "FORBIDDEN", "You cannot access this leave request")
		return
	}
	if status == "REJECTED" {
		var input struct {
			Reason string `json:"reason" binding:"required"`
		}
		if c.ShouldBindJSON(&input) != nil || strings.TrimSpace(input.Reason) == "" {
			fail(c, 400, "INVALID_REQUEST", "Rejection reason is required")
			return
		}
		value.RejectionReason = strings.TrimSpace(input.Reason)
	}
	if status == "CANCELLED" && value.Status != "PENDING" {
		fail(c, 409, "INVALID_STATUS", "Only pending requests can be cancelled")
		return
	}
	if value.Status != "PENDING" {
		fail(c, 409, "INVALID_STATUS", "Only pending requests can be processed")
		return
	}
	updates := map[string]interface{}{"status": status}
	if status == "APPROVED" {
		uid := c.MustGet("user_id").(uint)
		updates["approved_by"] = uid
		updates["approved_at"] = time.Now()
	}
	if status == "REJECTED" {
		updates["rejection_reason"] = value.RejectionReason
	}
	if status == "CANCELLED" {
		updates["cancelled_at"] = time.Now()
	}
	if err := s.db.Model(&value).Updates(updates).Error; err != nil {
		fail(c, 500, "UPDATE_FAILED", "Could not update leave request")
		return
	}
	s.db.Preload("Employee").Preload("Approver").Preload("Approver.Employee").First(&value, leaveID)
	ok(c, value)
}
func (s *Server) canAccessLeave(c *gin.Context, value model.LeaveRequest) bool {
	role, _ := c.Get("role")
	if role == "ADMIN" {
		return true
	}
	if role == "EMPLOYEE" {
		return value.EmployeeID == s.currentEmployee(c)
	}
	if role == "MANAGER" {
		var employee model.Employee
		return s.db.First(&employee, value.EmployeeID).Error == nil &&
			employee.ManagerID != nil && *employee.ManagerID == s.currentEmployee(c)
	}
	return false
}
func parseDate(value string) (time.Time, error) {
	return time.Parse("2006-01-02", value)
}
func (s *Server) dashboard(c *gin.Context) {
	var employees, departments, users, pending, present, absent int64
	s.db.Model(&model.Employee{}).Where("status = ?", "ACTIVE").Count(&employees)
	s.db.Model(&model.Department{}).Count(&departments)
	s.db.Model(&model.User{}).Where("is_active = ?", true).Count(&users)
	s.db.Model(&model.LeaveRequest{}).Where("status = ?", "PENDING").Count(&pending)
	s.db.Model(&model.Attendance{}).Where("date = ? AND status IN ?", time.Now().Truncate(24*time.Hour), []string{"PRESENT", "LATE"}).Count(&present)
	s.db.Model(&model.Employee{}).Where("status = ?", "ACTIVE").Count(&absent)
	ok(c, gin.H{"total_employees": employees, "total_departments": departments, "total_users": users, "pending_leaves": pending, "present_today": present, "absent_today": absent - present})
}
