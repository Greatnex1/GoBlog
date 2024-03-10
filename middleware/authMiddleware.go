package middleware

import (
	"GoAuthLogin/helpers"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
)

func Authenticate() gin.HandlerFunc {
	return func(context *gin.Context) {
		clientToken := context.Request.Header.Get("token")
		if clientToken == "" {
			context.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Authorization header not provided")})
			context.Abort()
			return
		}
		claims, err := helpers.ValidateToken(clientToken)
		if err != "" {
			context.JSON(http.StatusInternalServerError, gin.H{"error": err})
			context.Abort()
			return
		}
		context.Set("email", claims.Email)
		context.Set("firstname", claims.Firstname)
		context.Set("lastname", claims.Lastname)
		context.Set("uid", claims.Uid)
		context.Set("user_type", claims.UserType)
		context.Next()
	}

}
