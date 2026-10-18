package server

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"securehr/backend/internal/config"
)

type Server struct {
	db  *gorm.DB
	cfg config.Config
}

func New(db *gorm.DB, cfg config.Config) *Server {
	return &Server{db: db, cfg: cfg}
}

func (s *Server) Router() *gin.Engine {
	return registerRoutes(s, s.cfg)
}
