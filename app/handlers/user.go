package handlers

import (
	"context"
	"encoding/json"
	"net/http"

	"golang.org/x/crypto/bcrypt"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	ctx         = context.Background()
	redisClient *redis.Client
	mongoClient *mongo.Client
)

func init() {
	redisClient = redis.NewClient(&redis.Options{
		Addr: "redis_cache:6379",
	})

	mongoURI := "mongodb://root:example@mongo_db:27017"
	clientOptions := options.Client().ApplyURI(mongoURI)
	var err error
	mongoClient, err = mongo.Connect(ctx, clientOptions)
	if err != nil {
		panic(err)
	}
	err = mongoClient.Ping(ctx, nil)
	if err != nil {
		panic(err)
	}
}

type User struct {
	Username string `json:"username" bson:"username"`
	Password string `json:"password" bson:"password"`
}

func Register(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error hashing password"})
		return
	}
	user.Password = string(hashedPassword)

	collection := mongoClient.Database("project").Collection("users")
	_, err = collection.InsertOne(ctx, user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error registering user"})
		return
	}

	userJSON, _ := json.Marshal(user)
	redisClient.Set(ctx, user.Username, userJSON, 0)
	c.JSON(http.StatusCreated, gin.H{"message": "User registered"})
}

func Authorize(c *gin.Context) {
	var req User
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userJSON, err := redisClient.Get(ctx, req.Username).Result()
	if err == redis.Nil {
		collection := mongoClient.Database("project").Collection("users")
		err := collection.FindOne(ctx, bson.M{"username": req.Username}).Decode(&req)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
			return
		}
		userBytes, _ := json.Marshal(req)
		redisClient.Set(ctx, req.Username, string(userBytes), 0)
		userJSON = string(userBytes)
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error retrieving user"})
		return
	}

	var user User
	json.Unmarshal([]byte(userJSON), &user)

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Failed password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Authorized"})
}

func Delete(c *gin.Context) {
	var req User
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	collection := mongoClient.Database("project").Collection("users")
	_, err := collection.DeleteOne(ctx, bson.M{"username": req.Username})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error deleting user"})
		return
	}

	redisClient.Del(ctx, req.Username)
	c.JSON(http.StatusOK, gin.H{"message": "User deleted"})
}
