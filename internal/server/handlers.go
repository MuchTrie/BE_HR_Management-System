package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"net/http"
	"strconv"
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
	if s.db.Preload("Role").Preload("Employee.Department").Preload("Employee.Position").Preload("Employee.Manager").Where("email = ? AND is_active = ?", strings.ToLower(input.Email), true).First(&user).Error != nil || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(input.Password)) != nil {
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
	if s.db.Preload("Role").Preload("Employee.Department").Preload("Employee.Position").Preload("Employee.Manager").First(&user, stored.UserID).Error != nil || !user.IsActive {
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
	if s.db.Preload("Role").Preload("Employee.Department").Preload("Employee.Position").Preload("Employee.Manager").First(&user, uid).Error != nil {
		fail(c, 404, "NOT_FOUND", "User not found")
		return
	}
	ok(c, publicUser(user))
}
func publicUser(user model.User) gin.H {
	return gin.H{"id": user.ID, "email": user.Email, "role": user.Role.Name, "employee_id": user.EmployeeID, "employee": user.Employee}
}

type userResponse struct {
	ID         uint           `json:"id"`
	EmployeeID uint           `json:"employee_id"`
	Employee   model.Employee `json:"employee"`
	Email      string         `json:"email"`
	Role       string         `json:"role"`
	IsActive   bool           `json:"is_active"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
}

func newUserResponse(user model.User) userResponse {
	return userResponse{
		ID:         user.ID,
		EmployeeID: user.EmployeeID,
		Employee:   user.Employee,
		Email:      user.Email,
		Role:       user.Role.Name,
		IsActive:   user.IsActive,
		CreatedAt:  user.CreatedAt,
		UpdatedAt:  user.UpdatedAt,
	}
}

func (s *Server) listEmployees(c *gin.Context) {
	var employees []model.Employee
	q := s.db.Preload("Department").Preload("Position")
	role, _ := c.Get("role")
	if role == "MANAGER" {
		q = q.Where("manager_id = ?", s.currentEmployee(c))
	} else if role == "EMPLOYEE" {
		q = q.Where("id = ?", s.currentEmployee(c))
	}
	if search := c.Query("search"); search != "" {
		like := "%" + search + "%"
		q = q.Where("first_name LIKE ? OR last_name LIKE ? OR email LIKE ? OR employee_number LIKE ?", like, like, like, like)
	}
	if departmentID := c.Query("department_id"); departmentID != "" {
		value, err := strconv.ParseUint(departmentID, 10, 64)
		if err != nil || value == 0 {
			fail(c, http.StatusBadRequest, "INVALID_QUERY", "department_id must be a positive integer")
			return
		}
		q = q.Where("department_id = ?", value)
	}
	if positionID := c.Query("position_id"); positionID != "" {
		value, err := strconv.ParseUint(positionID, 10, 64)
		if err != nil || value == 0 {
			fail(c, http.StatusBadRequest, "INVALID_QUERY", "position_id must be a positive integer")
			return
		}
		q = q.Where("position_id = ?", value)
	}
	if gender := c.Query("gender"); gender != "" {
		if gender != "MALE" && gender != "FEMALE" {
			fail(c, http.StatusBadRequest, "INVALID_QUERY", "gender must be MALE or FEMALE")
			return
		}
		q = q.Where("gender = ?", gender)
	}
	if status := c.Query("status"); status != "" {
		q = q.Where("status = ?", status)
	}
	if dateFrom := c.Query("join_date_from"); dateFrom != "" {
		if _, err := parseDate(dateFrom); err != nil {
			fail(c, http.StatusBadRequest, "INVALID_QUERY", "join_date_from must use YYYY-MM-DD format")
			return
		}
		q = q.Where("join_date >= ?", dateFrom)
	}
	if dateTo := c.Query("join_date_to"); dateTo != "" {
		if _, err := parseDate(dateTo); err != nil {
			fail(c, http.StatusBadRequest, "INVALID_QUERY", "join_date_to must use YYYY-MM-DD format")
			return
		}
		q = q.Where("join_date <= ?", dateTo)
	}
	if dateFrom, dateTo := c.Query("join_date_from"), c.Query("join_date_to"); dateFrom != "" && dateTo != "" && dateTo < dateFrom {
		fail(c, http.StatusBadRequest, "INVALID_QUERY", "join_date_to cannot be before join_date_from")
		return
	}

	page, perPage, valid := paginationParams(c)
	if !valid {
		return
	}
	sortColumn, valid := employeeSortColumn(c.Query("sort_by"))
	if !valid {
		fail(c, http.StatusBadRequest, "INVALID_QUERY", "sort_by is not supported")
		return
	}
	sortOrder := strings.ToUpper(c.DefaultQuery("sort_order", "ASC"))
	if sortOrder != "ASC" && sortOrder != "DESC" {
		fail(c, http.StatusBadRequest, "INVALID_QUERY", "sort_order must be ASC or DESC")
		return
	}

	var total int64
	if err := q.Model(&model.Employee{}).Count(&total).Error; err != nil {
		fail(c, http.StatusInternalServerError, "LIST_FAILED", "Could not count employees")
		return
	}
	if err := q.Order(sortColumn + " " + sortOrder + ", id ASC").
		Offset((page - 1) * perPage).
		Limit(perPage).
		Find(&employees).Error; err != nil {
		fail(c, http.StatusInternalServerError, "LIST_FAILED", "Could not list employees")
		return
	}
	ok(c, gin.H{
		"items": employees, "total": total, "page": page, "per_page": perPage,
		"total_pages": int(math.Ceil(float64(total) / float64(perPage))),
	})
}

func paginationParams(c *gin.Context) (int, int, bool) {
	page := 1
	perPage := 10
	var err error
	if value := c.Query("page"); value != "" {
		page, err = strconv.Atoi(value)
		if err != nil || page < 1 {
			fail(c, http.StatusBadRequest, "INVALID_QUERY", "page must be a positive integer")
			return 0, 0, false
		}
	}
	if value := c.Query("per_page"); value != "" {
		perPage, err = strconv.Atoi(value)
		if err != nil || (perPage != 10 && perPage != 25 && perPage != 50) {
			fail(c, http.StatusBadRequest, "INVALID_QUERY", "per_page must be 10, 25, or 50")
			return 0, 0, false
		}
	}
	return page, perPage, true
}

func employeeSortColumn(value string) (string, bool) {
	columns := map[string]string{
		"id": "id", "employee_number": "employee_number", "first_name": "first_name",
		"last_name": "last_name", "email": "email", "phone": "phone",
		"date_of_birth": "date_of_birth", "gender": "gender",
		"department_id": "department_id", "position_id": "position_id",
		"manager_id": "manager_id", "join_date": "join_date", "status": "status",
		"created_at": "created_at", "updated_at": "updated_at",
	}
	if value == "" {
		return "first_name", true
	}
	column, ok := columns[value]
	return column, ok
}

func (s *Server) listUsers(c *gin.Context) {
	var users []model.User
	if err := s.db.Preload("Role").Preload("Employee").Find(&users).Error; err != nil {
		fail(c, http.StatusInternalServerError, "DATABASE_ERROR", "Could not load users")
		return
	}

	response := make([]userResponse, 0, len(users))
	for _, user := range users {
		response = append(response, newUserResponse(user))
	}
	ok(c, response)
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
	if err := s.db.Preload("Role").Preload("Employee").First(&user, userID).Error; err != nil {
		fail(c, http.StatusInternalServerError, "DATABASE_ERROR", "Could not load updated user")
		return
	}
	ok(c, newUserResponse(user))
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
	} else if role == "EMPLOYEE" {
		q = q.Where("employee_id = ?", s.currentEmployee(c))
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
	policy, err := s.leavePolicy(input.LeaveType)
	if err != nil {
		fail(c, http.StatusBadRequest, "INVALID_LEAVE_TYPE", "Unsupported leave type")
		return
	}
	days, valid, ruleMessage := s.validateLeaveDates(startDate, endDate, policy)
	if !valid {
		fail(c, http.StatusConflict, "LEAVE_RULE_VIOLATION", ruleMessage)
		return
	}
	if !s.hasLeaveBalance(employeeID, input.LeaveType, startDate.Year(), days, 0) {
		fail(c, http.StatusConflict, "LEAVE_QUOTA_EXCEEDED", "Leave request exceeds the available quota")
		return
	}
	var overlap int64
	s.db.Model(&model.LeaveRequest{}).Where("employee_id = ? AND status IN ? AND start_date <= ? AND end_date >= ?", employeeID, []string{"PENDING", "APPROVED"}, endDate, startDate).Count(&overlap)
	if overlap > 0 {
		fail(c, 409, "LEAVE_OVERLAP", "Leave dates overlap an existing request")
		return
	}
	value := model.LeaveRequest{EmployeeID: employeeID, LeaveType: input.LeaveType, StartDate: startDate, EndDate: endDate, Reason: input.Reason, Status: "PENDING", RequiredLevels: policy.RequiredApprovalLevels}
	if s.db.Create(&value).Error != nil {
		fail(c, 500, "CREATE_FAILED", "Could not create leave request")
		return
	}
	s.recordLeaveHistory(value.ID, "", "PENDING", c.MustGet("user_id").(uint), "Leave request created")
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
	actorID := c.MustGet("user_id").(uint)
	if status == "APPROVED" && value.RequiredLevels > value.ApprovalLevel+1 {
		if c.GetString("role") != "ADMIN" {
			if !s.canAccessLeave(c, value) {
				fail(c, http.StatusForbidden, "FORBIDDEN", "You cannot approve this leave request")
				return
			}
		}
		nextLevel := value.ApprovalLevel + 1
		if err := s.db.Model(&value).Update("approval_level", nextLevel).Error; err != nil {
			fail(c, http.StatusInternalServerError, "UPDATE_FAILED", "Could not record approval level")
			return
		}
		s.recordLeaveHistory(value.ID, value.Status, value.Status, actorID, fmt.Sprintf("Approval level %d completed", nextLevel))
		value.ApprovalLevel = nextLevel
		s.db.Preload("Employee").First(&value, leaveID)
		ok(c, value)
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
	reason := value.RejectionReason
	if status == "APPROVED" {
		reason = "Leave approved"
	}
	if status == "CANCELLED" {
		reason = "Leave cancelled"
	}
	s.recordLeaveHistory(value.ID, value.Status, status, actorID, reason)
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
		if s.db.First(&employee, value.EmployeeID).Error == nil &&
			employee.ManagerID != nil && *employee.ManagerID == s.currentEmployee(c) {
			return true
		}
		var delegation model.ApprovalDelegation
		today := dateOnly(time.Now())
		return s.db.Where("manager_id = ? AND delegate_id = ? AND start_date <= ? AND end_date >= ?",
			employee.ManagerID, s.currentEmployee(c), today, today).First(&delegation).Error == nil
	}
	return false
}
func parseDate(value string) (time.Time, error) {
	return time.Parse("2006-01-02", value)
}

func (s *Server) leavePolicy(leaveType string) (model.LeavePolicy, error) {
	var policy model.LeavePolicy
	err := s.db.Where("leave_type = ?", leaveType).First(&policy).Error
	return policy, err
}

func (s *Server) validateLeaveDates(start, end time.Time, policy model.LeavePolicy) (int, bool, string) {
	days := 0
	for date := dateOnly(start); !date.After(dateOnly(end)); date = date.AddDate(0, 0, 1) {
		if !policy.AllowWeekend && (date.Weekday() == time.Saturday || date.Weekday() == time.Sunday) {
			return 0, false, "Tanggal cuti tidak boleh jatuh pada weekend."
		}
		var holiday model.CompanyHoliday
		if s.db.Where("date = ?", date).Limit(1).Find(&holiday).Error != nil {
			return 0, false, "Tidak dapat memeriksa kalender hari libur."
		}
		if holiday.ID != 0 {
			return 0, false, "Tanggal cuti tidak boleh jatuh pada hari libur perusahaan."
		}
		days++
	}
	if days == 0 || (policy.MaxConsecutiveDays > 0 && days > policy.MaxConsecutiveDays) {
		return 0, false, fmt.Sprintf("Durasi cuti melebihi batas maksimal %d hari.", policy.MaxConsecutiveDays)
	}
	return days, true, ""
}

func (s *Server) leaveDays(start, end time.Time) int {
	days := 0
	for date := dateOnly(start); !date.After(dateOnly(end)); date = date.AddDate(0, 0, 1) {
		var holiday model.CompanyHoliday
		if date.Weekday() != time.Saturday && date.Weekday() != time.Sunday {
			s.db.Where("date = ?", date).Limit(1).Find(&holiday)
		}
		if date.Weekday() != time.Saturday && date.Weekday() != time.Sunday && holiday.ID == 0 {
			days++
		}
	}
	return days
}

func (s *Server) hasLeaveBalance(employeeID uint, leaveType string, year, requested int, excludeID uint) bool {
	policy, err := s.leavePolicy(leaveType)
	if err != nil {
		return false
	}
	var requests []model.LeaveRequest
	query := s.db.Where("employee_id = ? AND leave_type = ? AND status IN ? AND start_date >= ? AND start_date < ?",
		employeeID, leaveType, []string{"PENDING", "APPROVED"},
		time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(year+1, 1, 1, 0, 0, 0, 0, time.UTC))
	if excludeID > 0 {
		query = query.Where("id <> ?", excludeID)
	}
	if query.Find(&requests).Error != nil {
		return false
	}
	used := requested
	for _, request := range requests {
		used += s.leaveDays(request.StartDate, request.EndDate)
	}
	return used <= policy.AnnualQuotaDays
}

func (s *Server) recordLeaveHistory(leaveID uint, from, to string, changedBy uint, reason string) {
	_ = s.db.Create(&model.LeaveStatusHistory{
		LeaveID: leaveID, FromStatus: from, ToStatus: to, ChangedBy: changedBy, Reason: reason,
	}).Error
}

func (s *Server) leaveBalance(c *gin.Context) {
	employeeID := s.currentEmployee(c)
	if employeeID == 0 {
		return
	}
	year := time.Now().Year()
	if value := c.Query("year"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 2000 || parsed > 2100 {
			fail(c, http.StatusBadRequest, "INVALID_YEAR", "Invalid leave balance year")
			return
		}
		year = parsed
	}
	var policies []model.LeavePolicy
	if err := s.db.Order("id").Find(&policies).Error; err != nil {
		fail(c, http.StatusInternalServerError, "DATABASE_ERROR", "Could not load leave policies")
		return
	}
	type balanceResponse struct {
		LeaveType string `json:"leave_type"`
		Quota     int    `json:"quota"`
		Used      int    `json:"used"`
		Remaining int    `json:"remaining"`
		Year      int    `json:"year"`
	}
	result := make([]balanceResponse, 0, len(policies))
	for _, policy := range policies {
		var requests []model.LeaveRequest
		s.db.Where("employee_id = ? AND leave_type = ? AND status IN ? AND start_date >= ? AND start_date < ?",
			employeeID, policy.LeaveType, []string{"PENDING", "APPROVED"},
			time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(year+1, 1, 1, 0, 0, 0, 0, time.UTC)).Find(&requests)
		used := 0
		for _, request := range requests {
			used += s.leaveDays(request.StartDate, request.EndDate)
		}
		result = append(result, balanceResponse{LeaveType: policy.LeaveType, Quota: policy.AnnualQuotaDays, Used: used, Remaining: maxInt(policy.AnnualQuotaDays-used, 0), Year: year})
	}
	ok(c, result)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (s *Server) listLeavePolicies(c *gin.Context) {
	var policies []model.LeavePolicy
	if err := s.db.Order("id").Find(&policies).Error; err != nil {
		fail(c, http.StatusInternalServerError, "DATABASE_ERROR", "Could not load leave policies")
		return
	}
	ok(c, policies)
}

func (s *Server) updateLeavePolicy(c *gin.Context) {
	policyID, valid := id(c)
	if !valid {
		fail(c, http.StatusBadRequest, "INVALID_ID", "Invalid policy id")
		return
	}
	var policy model.LeavePolicy
	if s.db.First(&policy, policyID).Error != nil {
		fail(c, http.StatusNotFound, "NOT_FOUND", "Leave policy not found")
		return
	}
	var input struct {
		AnnualQuotaDays        int  `json:"annual_quota_days" binding:"required"`
		MaxConsecutiveDays     int  `json:"max_consecutive_days"`
		AllowWeekend           bool `json:"allow_weekend"`
		RequiredApprovalLevels int  `json:"required_approval_levels" binding:"required"`
	}
	if c.ShouldBindJSON(&input) != nil || input.AnnualQuotaDays < 0 || input.RequiredApprovalLevels < 1 {
		fail(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid leave policy")
		return
	}
	if err := s.db.Model(&policy).Updates(map[string]interface{}{
		"annual_quota_days": input.AnnualQuotaDays, "max_consecutive_days": input.MaxConsecutiveDays,
		"allow_weekend": input.AllowWeekend, "required_approval_levels": input.RequiredApprovalLevels,
	}).Error; err != nil {
		fail(c, http.StatusInternalServerError, "UPDATE_FAILED", "Could not update leave policy")
		return
	}
	s.db.First(&policy, policyID)
	ok(c, policy)
}

func (s *Server) listHolidays(c *gin.Context) {
	var holidays []model.CompanyHoliday
	query := s.db.Order("date ASC")
	if year := c.Query("year"); year != "" {
		parsed, err := strconv.Atoi(year)
		if err != nil || parsed < 1 {
			fail(c, http.StatusBadRequest, "INVALID_YEAR", "Year must be a positive integer")
			return
		}
		query = query.Where("date >= ? AND date < ?", year+"-01-01", strconv.Itoa(parsed+1)+"-01-01")
	}
	if err := query.Find(&holidays).Error; err != nil {
		fail(c, http.StatusInternalServerError, "DATABASE_ERROR", "Could not load holidays")
		return
	}
	ok(c, holidays)
}

func (s *Server) createHoliday(c *gin.Context) {
	var input struct {
		Date string `json:"date" binding:"required"`
		Name string `json:"name" binding:"required"`
	}
	if c.ShouldBindJSON(&input) != nil {
		fail(c, http.StatusBadRequest, "INVALID_REQUEST", "Holiday date and name are required")
		return
	}
	date, err := parseDate(input.Date)
	if err != nil {
		fail(c, http.StatusBadRequest, "INVALID_DATE", "Date must use YYYY-MM-DD format")
		return
	}
	name := strings.TrimSpace(input.Name)
	if name == "" {
		fail(c, http.StatusBadRequest, "INVALID_REQUEST", "Holiday name is required")
		return
	}
	holiday := model.CompanyHoliday{Date: date, Name: name}
	var existing int64
	if err := s.db.Model(&model.CompanyHoliday{}).Where("date = ?", date).Count(&existing).Error; err != nil {
		fail(c, http.StatusInternalServerError, "DATABASE_ERROR", "Could not check holiday date")
		return
	}
	if existing > 0 {
		fail(c, http.StatusConflict, "DUPLICATE", "Holiday already exists")
		return
	}
	if err := s.db.Create(&holiday).Error; err != nil {
		fail(c, http.StatusInternalServerError, "DATABASE_ERROR", "Could not create holiday")
		return
	}
	created(c, holiday)
}

func (s *Server) updateHoliday(c *gin.Context) {
	holidayID, valid := id(c)
	if !valid {
		fail(c, http.StatusBadRequest, "INVALID_ID", "Invalid holiday id")
		return
	}
	var holiday model.CompanyHoliday
	if s.db.First(&holiday, holidayID).Error != nil {
		fail(c, http.StatusNotFound, "NOT_FOUND", "Holiday not found")
		return
	}
	var input struct {
		Date string `json:"date" binding:"required"`
		Name string `json:"name" binding:"required"`
	}
	if c.ShouldBindJSON(&input) != nil {
		fail(c, http.StatusBadRequest, "INVALID_REQUEST", "Holiday date and name are required")
		return
	}
	date, err := parseDate(input.Date)
	if err != nil {
		fail(c, http.StatusBadRequest, "INVALID_DATE", "Date must use YYYY-MM-DD format")
		return
	}
	name := strings.TrimSpace(input.Name)
	if name == "" {
		fail(c, http.StatusBadRequest, "INVALID_REQUEST", "Holiday name is required")
		return
	}
	var existing int64
	if err := s.db.Model(&model.CompanyHoliday{}).Where("date = ? AND id <> ?", date, holidayID).Count(&existing).Error; err != nil {
		fail(c, http.StatusInternalServerError, "DATABASE_ERROR", "Could not check holiday date")
		return
	}
	if existing > 0 {
		fail(c, http.StatusConflict, "DUPLICATE", "Holiday date already exists")
		return
	}
	if err := s.db.Model(&holiday).Updates(map[string]interface{}{"date": date, "name": name}).Error; err != nil {
		fail(c, http.StatusInternalServerError, "DATABASE_ERROR", "Could not update holiday")
		return
	}
	s.db.First(&holiday, holidayID)
	ok(c, holiday)
}

func (s *Server) deleteHoliday(c *gin.Context) {
	holidayID, valid := id(c)
	if !valid {
		fail(c, http.StatusBadRequest, "INVALID_ID", "Invalid holiday id")
		return
	}
	result := s.db.Delete(&model.CompanyHoliday{}, holidayID)
	if result.Error != nil {
		fail(c, http.StatusInternalServerError, "DELETE_FAILED", "Could not delete holiday")
		return
	}
	if result.RowsAffected == 0 {
		fail(c, http.StatusNotFound, "NOT_FOUND", "Holiday not found")
		return
	}
	c.Status(http.StatusNoContent)
}

func (s *Server) listApprovalDelegations(c *gin.Context) {
	var values []model.ApprovalDelegation
	query := s.db.Order("start_date DESC")
	if c.GetString("role") == "MANAGER" {
		query = query.Where("manager_id = ?", s.currentEmployee(c))
	}
	if err := query.Find(&values).Error; err != nil {
		fail(c, http.StatusInternalServerError, "DATABASE_ERROR", "Could not load approval delegations")
		return
	}
	ok(c, values)
}

func (s *Server) createApprovalDelegation(c *gin.Context) {
	var input struct {
		DelegateID uint   `json:"delegate_id" binding:"required"`
		StartDate  string `json:"start_date" binding:"required"`
		EndDate    string `json:"end_date" binding:"required"`
	}
	if c.ShouldBindJSON(&input) != nil {
		fail(c, http.StatusBadRequest, "INVALID_REQUEST", "Delegation fields are required")
		return
	}
	start, startErr := parseDate(input.StartDate)
	end, endErr := parseDate(input.EndDate)
	managerID := s.currentEmployee(c)
	if startErr != nil || endErr != nil || end.Before(start) || input.DelegateID == managerID {
		fail(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid delegation dates or delegate")
		return
	}
	var delegate model.Employee
	if s.db.Where("id = ? AND status = ?", input.DelegateID, "ACTIVE").First(&delegate).Error != nil {
		fail(c, http.StatusNotFound, "NOT_FOUND", "Delegate employee not found")
		return
	}
	value := model.ApprovalDelegation{ManagerID: managerID, DelegateID: input.DelegateID, StartDate: start, EndDate: end}
	if err := s.db.Create(&value).Error; err != nil {
		fail(c, http.StatusConflict, "DUPLICATE", "Delegation could not be created")
		return
	}
	created(c, value)
}

func (s *Server) updateLeave(c *gin.Context) {
	leaveID, valid := id(c)
	if !valid {
		fail(c, http.StatusBadRequest, "INVALID_ID", "Invalid leave id")
		return
	}
	var leave model.LeaveRequest
	if s.db.First(&leave, leaveID).Error != nil || !s.canAccessLeave(c, leave) || leave.Status != "PENDING" {
		fail(c, http.StatusConflict, "INVALID_STATUS", "Only accessible pending leave can be edited")
		return
	}
	var input struct {
		LeaveType string `json:"leave_type" binding:"required"`
		StartDate string `json:"start_date" binding:"required"`
		EndDate   string `json:"end_date" binding:"required"`
		Reason    string `json:"reason" binding:"required"`
	}
	if c.ShouldBindJSON(&input) != nil {
		fail(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid leave payload")
		return
	}
	start, startErr := parseDate(input.StartDate)
	end, endErr := parseDate(input.EndDate)
	policy, policyErr := s.leavePolicy(input.LeaveType)
	if startErr != nil || endErr != nil || policyErr != nil || end.Before(start) {
		fail(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid leave dates or type")
		return
	}
	days, validDates, ruleMessage := s.validateLeaveDates(start, end, policy)
	if !validDates || !s.hasLeaveBalance(leave.EmployeeID, input.LeaveType, start.Year(), days, leave.ID) {
		if !validDates {
			fail(c, http.StatusConflict, "LEAVE_RULE_VIOLATION", ruleMessage)
		} else {
			fail(c, http.StatusConflict, "LEAVE_QUOTA_EXCEEDED", "Pengajuan cuti melebihi sisa kuota cuti Anda.")
		}
		return
	}
	if err := s.db.Model(&leave).Updates(map[string]interface{}{"leave_type": input.LeaveType, "start_date": start, "end_date": end, "reason": strings.TrimSpace(input.Reason), "required_levels": policy.RequiredApprovalLevels}).Error; err != nil {
		fail(c, http.StatusInternalServerError, "UPDATE_FAILED", "Could not update leave request")
		return
	}
	s.db.Preload("Employee").First(&leave, leave.ID)
	ok(c, leave)
}

func (s *Server) leaveHistory(c *gin.Context) {
	leaveID, valid := id(c)
	if !valid {
		fail(c, http.StatusBadRequest, "INVALID_ID", "Invalid leave id")
		return
	}
	var leave model.LeaveRequest
	if s.db.First(&leave, leaveID).Error != nil || !s.canAccessLeave(c, leave) {
		fail(c, http.StatusForbidden, "FORBIDDEN", "You cannot access this leave history")
		return
	}
	var history []model.LeaveStatusHistory
	if err := s.db.Where("leave_id = ?", leaveID).Order("created_at ASC").Find(&history).Error; err != nil {
		fail(c, http.StatusInternalServerError, "DATABASE_ERROR", "Could not load leave history")
		return
	}
	ok(c, history)
}

func dateOnly(value time.Time) time.Time {
	return time.Date(value.Year(), value.Month(), value.Day(), 0, 0, 0, 0, value.Location())
}

func (s *Server) dashboard(c *gin.Context) {
	preset := c.DefaultQuery("preset", "this_month")
	start, end, valid := dashboardPeriod(preset, time.Now())
	if !valid {
		fail(c, http.StatusBadRequest, "INVALID_QUERY", "preset must be this_month, last_3_months, or this_year")
		return
	}

	employeeQuery := s.dashboardEmployeeQuery(c)
	var employees []model.Employee
	if err := employeeQuery.Preload("Department").Find(&employees).Error; err != nil {
		fail(c, http.StatusInternalServerError, "DATABASE_ERROR", "Could not load dashboard employees")
		return
	}
	employeeIDs := make([]uint, 0, len(employees))
	for _, employee := range employees {
		employeeIDs = append(employeeIDs, employee.ID)
	}

	var attendance []model.Attendance
	attendanceQuery := s.db.Where("date >= ? AND date <= ?", start, end)
	if len(employeeIDs) > 0 {
		attendanceQuery = attendanceQuery.Where("employee_id IN ?", employeeIDs)
	} else {
		attendanceQuery = attendanceQuery.Where("1 = 0")
	}
	if err := attendanceQuery.Find(&attendance).Error; err != nil {
		fail(c, http.StatusInternalServerError, "DATABASE_ERROR", "Could not load dashboard attendance")
		return
	}

	var leaves []model.LeaveRequest
	leaveQuery := s.db.Where("start_date <= ? AND end_date >= ?", end, start)
	if len(employeeIDs) > 0 {
		leaveQuery = leaveQuery.Where("employee_id IN ?", employeeIDs)
	} else {
		leaveQuery = leaveQuery.Where("1 = 0")
	}
	if err := leaveQuery.Find(&leaves).Error; err != nil {
		fail(c, http.StatusInternalServerError, "DATABASE_ERROR", "Could not load dashboard leaves")
		return
	}

	departmentCounts := map[string]int{}
	employeeStatusCounts := map[string]int{}
	attendanceStatusCounts := map[string]int{}
	leaveStatusCounts := map[string]int{}
	leaveMonthly := map[string]int{}
	lateCount := 0
	for _, employee := range employees {
		employeeStatusCounts[employee.Status]++
		if employee.Department != nil {
			departmentCounts[employee.Department.Name]++
		} else {
			departmentCounts["Unassigned"]++
		}
	}
	for _, record := range attendance {
		attendanceStatusCounts[record.Status]++
		if record.Status == "LATE" {
			lateCount++
		}
	}
	for _, leave := range leaves {
		leaveStatusCounts[leave.Status]++
		month := leave.StartDate.Format("2006-01")
		leaveMonthly[month]++
	}

	activeEmployees := employeeStatusCounts["ACTIVE"]
	today := dateOnly(time.Now())
	presentToday := 0
	for _, record := range attendance {
		if dateOnly(record.Date).Equal(today) && (record.Status == "PRESENT" || record.Status == "LATE") {
			presentToday++
		}
	}

	var users int64
	if c.GetString("role") == "ADMIN" {
		s.db.Model(&model.User{}).Where("is_active = ?", true).Count(&users)
	}
	ok(c, gin.H{
		"preset":                   preset,
		"period_start":             start.Format("2006-01-02"),
		"period_end":               end.Format("2006-01-02"),
		"total_employees":          activeEmployees,
		"total_departments":        len(departmentCounts),
		"total_users":              users,
		"pending_leaves":           leaveStatusCounts["PENDING"],
		"present_today":            presentToday,
		"absent_today":             maxInt(activeEmployees-presentToday, 0),
		"department_counts":        departmentCounts,
		"attendance_status_counts": attendanceStatusCounts,
		"leave_monthly":            leaveMonthly,
		"leave_status_counts":      leaveStatusCounts,
		"employee_status_counts":   employeeStatusCounts,
		"late_attendance":          lateCount,
	})
}

func dashboardPeriod(preset string, now time.Time) (time.Time, time.Time, bool) {
	today := dateOnly(now)
	switch preset {
	case "this_month":
		return time.Date(today.Year(), today.Month(), 1, 0, 0, 0, 0, today.Location()), today, true
	case "last_3_months":
		start := time.Date(today.Year(), today.Month(), 1, 0, 0, 0, 0, today.Location()).AddDate(0, -2, 0)
		return start, today, true
	case "this_year":
		return time.Date(today.Year(), 1, 1, 0, 0, 0, 0, today.Location()), today, true
	default:
		return time.Time{}, time.Time{}, false
	}
}

func (s *Server) dashboardEmployeeQuery(c *gin.Context) *gorm.DB {
	query := s.db.Model(&model.Employee{})
	switch c.GetString("role") {
	case "EMPLOYEE":
		query = query.Where("id = ?", s.currentEmployee(c))
	case "MANAGER":
		query = query.Where("manager_id = ?", s.currentEmployee(c))
	}
	return query
}
