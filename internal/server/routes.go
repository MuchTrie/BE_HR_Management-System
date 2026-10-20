package server

import (
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"securehr/backend/internal/config"
	"securehr/backend/internal/middleware"
)

func registerRoutes(s *Server, cfg config.Config) *gin.Engine {
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery(), cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:5173", "http://127.0.0.1:5173"},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		AllowCredentials: true,
	}))
	api := r.Group("/api/v1")
	api.POST("/auth/login", s.login)
	api.POST("/auth/refresh", s.refresh)
	protected := api.Group("")
	protected.Use(middleware.RequireAuth(cfg.JWTSecret))
	protected.POST("/auth/logout", s.logout)
	protected.GET("/auth/me", s.me)
	protected.GET("/dashboard/stats", s.dashboard)
	protected.GET("/users", middleware.RequireRoles("ADMIN"), s.listUsers)
	protected.PATCH("/users/:id/status", middleware.RequireRoles("ADMIN"), s.toggleUserStatus)
	protected.GET("/employees", s.listEmployees)
	protected.POST("/employees", middleware.RequireRoles("ADMIN"), s.createEmployee)
	protected.GET("/employees/:id", s.getEmployee)
	protected.PUT("/employees/:id", middleware.RequireRoles("ADMIN"), s.updateEmployee)
	protected.DELETE("/employees/:id", middleware.RequireRoles("ADMIN"), s.deleteEmployee)
	protected.GET("/departments", s.listDepartments)
	protected.GET("/departments/:id", s.getDepartment)
	protected.POST("/departments", middleware.RequireRoles("ADMIN"), s.createDepartment)
	protected.PUT("/departments/:id", middleware.RequireRoles("ADMIN"), s.updateDepartment)
	protected.DELETE("/departments/:id", middleware.RequireRoles("ADMIN"), s.deleteDepartment)
	protected.GET("/positions", s.listPositions)
	protected.GET("/positions/:id", s.getPosition)
	protected.POST("/positions", middleware.RequireRoles("ADMIN"), s.createPosition)
	protected.PUT("/positions/:id", middleware.RequireRoles("ADMIN"), s.updatePosition)
	protected.DELETE("/positions/:id", middleware.RequireRoles("ADMIN"), s.deletePosition)
	protected.POST("/attendance/check-in", s.checkIn)
	protected.POST("/attendance/check-out", s.checkOut)
	protected.GET("/attendance", s.listAttendance)
	protected.POST("/leaves", s.createLeave)
	protected.GET("/leaves", s.listLeaves)
	protected.GET("/leaves/balance", s.leaveBalance)
	protected.GET("/leave-policies", s.listLeavePolicies)
	protected.PATCH("/leave-policies/:id", middleware.RequireRoles("ADMIN"), s.updateLeavePolicy)
	protected.GET("/holidays", s.listHolidays)
	protected.POST("/holidays", middleware.RequireRoles("ADMIN"), s.createHoliday)
	protected.GET("/approval-delegations", s.listApprovalDelegations)
	protected.POST("/approval-delegations", middleware.RequireRoles("MANAGER", "ADMIN"), s.createApprovalDelegation)
	protected.GET("/leaves/:id", s.getLeave)
	protected.PUT("/leaves/:id", s.updateLeave)
	protected.GET("/leaves/:id/history", s.leaveHistory)
	protected.POST("/leaves/:id/approve", middleware.RequireRoles("ADMIN", "MANAGER"), s.approveLeave)
	protected.POST("/leaves/:id/reject", middleware.RequireRoles("ADMIN", "MANAGER"), s.rejectLeave)
	protected.POST("/leaves/:id/cancel", s.cancelLeave)
	return r
}
