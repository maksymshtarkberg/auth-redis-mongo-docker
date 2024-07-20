package main

import (
	"myproject/handlers"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	r.POST("/api/v1/register", handlers.Register)
	r.POST("/api/v1/authorization", handlers.Authorize)
	r.POST("/api/v1/delete", handlers.Delete)

	r.Run(":8045")
}
