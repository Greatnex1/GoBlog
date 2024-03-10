package routes

import (
	"GoAuthLogin/controller"
	"github.com/gin-gonic/gin"
)

func AuthRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.POST("users/signup", controller.SignUp())
	incomingRoutes.POST("users/login", controller.Login())
}
