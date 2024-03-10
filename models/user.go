package models

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

type User struct {
	ID            primitive.ObjectID `bson:"_id"`
	Firstname     *string            `json:"firstname" validate:"required,min=2,max=100"`
	Lastname      *string            `json:"lastname" validate:"required,min=2,max=100"`
	Email         *string            `json:"email" validate:"email,required"`
	Password      *string            `json:"password" validate:"required,min=6"`
	Phonenumber   *string            `json:"phone_number" validate:"required"`
	User_type     *string            `json:"user_type" validate:"required,eq=ADMIN|eq=USER"`
	Token         *string            `json:"token" `
	Refresh_token *string            `json:"refresh_token" `
	Created_at    time.Time          `json:"created_At" `
	Updated_at    time.Time          `json:"updated_At" `
	User_id       string             `json:"user_Id"`
}
