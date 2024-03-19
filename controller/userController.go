package controller

import (
	"GoAuthLogin/database"
	"GoAuthLogin/helpers"
	"GoAuthLogin/models"
	"context"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"strconv"

	//"strconv"
	"time"
)

var userCollection *mongo.Collection = database.OPenCollection(database.Client, "user")

var validate = validator.New()

func HashPassword(password string) string {
	//bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		fmt.Println("Error in hashing password", err)

	}

	fmt.Println("Hashed password: ", string(bytes))
	return string(bytes)
}

func VerifyPassword(userPassword, providedPassword string) (bool, string) {
	err := bcrypt.CompareHashAndPassword([]byte(userPassword), []byte(providedPassword))
	log.Printf("user password: %s", []byte(userPassword))
	log.Printf("provided password: %s", []byte(providedPassword))
	fmt.Println("Hashed password: ", providedPassword)
	fmt.Println("Unhashed password: ", userPassword)
	check := true
	msg := ""
	if err != nil {
		msg = fmt.Sprintf(" password could not be verified")
		check = false
	}
	return check, msg
}

//func VerifyPassword(userPassword, providedPassword string) error {
//	return bcrypt.CompareHashAndPassword([]byte(userPassword), []byte(providedPassword))
//}

func SignUp() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		var user models.User
		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		validationErr := validate.Struct(user)
		if validationErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": validationErr.Error()})
			return

		}

		count, err := userCollection.CountDocuments(ctx, bson.M{"email": user.Email})

		defer cancel()
		if err != nil {
			log.Panic(err)
			//c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while checkimg for the email"})
		}
		password := HashPassword(*user.Password)
		user.Password = &password
		//count, err := userCollection.CountDocuments(ctx, bson.M{"phone": user.Phonenumber})

		//defer cancel()
		//if err != nil {
		//	log.Panic(err)
		//	c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while checking for the email"})
		//}
		count, err = userCollection.CountDocuments(ctx, bson.M{"phone": user.Phonenumber})

		defer cancel()
		if err != nil {
			log.Panic(err)
			//	c.JSON(http.StatusInternalServerError, gin.H{"error": "error occurred while checking for the phone number"})
		}
		if count > 0 {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "This email or phone number already exist"})
		}
		user.Created_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.Updated_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.ID = primitive.NewObjectID()
		user.User_id = user.ID.Hex()
		token, refreshToken, _ := helpers.GenerateAllToken(*user.Email, *user.Firstname, *user.Lastname, *user.User_type, *&user.User_id)
		user.Token = &token
		user.Refresh_token = &refreshToken
		resultInsertionNumber, InsertErr := userCollection.InsertOne(ctx, user)
		if InsertErr != nil {
			msg := fmt.Sprintf("User item was not created")
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return

		}
		defer cancel()

		c.JSON(http.StatusOK, resultInsertionNumber)
		//fmt.Sprintf("user details :%s ", *user.Email)
		log.Printf("user's saved email :%s user's saved password: %s ", *user.Email, *user.Password)

	}

}

func Login() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)

		var user models.User
		var foundUser models.User
		defer cancel()
		if err := c.BindJSON(&user); err != nil {
			log.Printf("Invalid email")
			c.JSON(http.StatusBadRequest, gin.H{"error": "email not allowed"})
			return
		}

		err := userCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&foundUser)
		log.Printf("USER'S EMAIL: %s", *foundUser.Email)

		defer cancel()
		if err != nil {
			//c.JSON(http.StatusInternalServerError, gin.H{"error": "email or password is incorrect"})
			return
		}

		//check if password input correlate with what used during sign up
		//err = userCollection.FindOne(ctx, bson.M{"password": user.Password}).Decode(&foundUser)
		//defer cancel()
		////	if password does not correlate throw an error
		//if err := c.BindJSON(&user); err != nil {
		//	c.JSON(http.StatusBadRequest, gin.H{"password": "A wrong password input"})
		//	//return
		//}
		if foundUser.Email == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "user not found"})
		}
		passwordIsValid, msg := VerifyPassword(*user.Password, *foundUser.Password)
		defer cancel()
		if passwordIsValid != true {
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}

		//return a token when login is successful
		token, refreshToken, _ := helpers.GenerateAllToken(*foundUser.Email, *foundUser.Firstname, *foundUser.Lastname, *foundUser.User_type, foundUser.User_id)
		helpers.UpdateAllToken(token, refreshToken, foundUser.User_id)
		err = userCollection.FindOne(ctx, bson.M{"user_id": foundUser.User_id}).Decode(&foundUser)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "server error"})
			return
		}
		c.JSON(http.StatusOK, foundUser)
		//return
	}
}

func GetUsers() gin.HandlerFunc {
	return func(c *gin.Context) {
		err := helpers.CheckUserType(c, "ADMIN")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		recordPerPage, err := strconv.Atoi(c.Query("recordPerPage"))
		if err != nil || recordPerPage < 1 {
			recordPerPage = 10
		}
		page, err1 := strconv.Atoi(c.Query("page"))
		if err1 != nil || page < 1 {
			page = 1
		}
		startIndex := (page - 1) * recordPerPage
		startIndex, err = strconv.Atoi(c.Query("startIndex"))

		matchStage := bson.D{{"$match", bson.D{{}}}}
		groupStage := bson.D{{"$group", bson.D{{"_id", bson.D{{"_id", "null"}}},
			{"total_count", bson.D{{"$sum", 1}}},
			{"data", bson.D{{"$push", "$$ROOT"}}}}}}

		projectStage := bson.D{
			{"$project", bson.D{
				{"_id", 0},
				{"total_count", 1},
				{"user_items", bson.D{{"$slice", []interface{}{"$data", startIndex, recordPerPage}}}}}}}
		result, err := userCollection.Aggregate(ctx, mongo.Pipeline{
			matchStage, groupStage, projectStage,
		})
		defer cancel()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occurred while listing user items"})
		}
		var allUsers []bson.M

		if err = result.All(ctx, &allUsers); err != nil {
			log.Fatal(err)
		}
		c.JSON(http.StatusOK, allUsers[0])
	}
}

func GetUser() gin.HandlerFunc {
	return func(c *gin.Context) {

		userId := c.Param("user_id")

		if err := helpers.MatchUserTypeToUid(c, userId); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		var user models.User
		err := userCollection.FindOne(ctx, bson.M{"user_id": userId}).Decode(&user)
		defer cancel()

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		c.JSON(http.StatusOK, user)
	}
}
