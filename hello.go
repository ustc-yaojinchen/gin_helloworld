package main

import (
	"net/mail"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var key = []byte("password")
var validtime int64 = 3600

type User struct {
	ID       uint   `id:""`
	Username string `username:""`
	Email    string `email:""`
	Password string `password:""`
}

func main() {
	router := gin.Default()
	router.POST("/create", create)
	router.POST("/delete", delete)
	router.GET("/login", login)
	router.GET("/logout", logout)
	router.POST("/update", update)
	router.GET("/showall", showall)
	router.Run(":8001")

}

func create(c *gin.Context) {
	db, err := gorm.Open(mysql.Open("root:123456@tcp(localhost:3306)/gobase"), &gorm.Config{})
	if err != nil {
		c.JSON(202, "连接数据库失败")
		return
	}

	var user User
	err = c.Bind(&user)
	if err != nil {
		c.JSON(202, "err")
		return
	}

	_, err = mail.ParseAddress(user.Email)
	if err != nil {
		c.JSON(202, "请输入正确的邮箱")
		return
	}

	var temp User
	db.Table("account").Where("username = ?", user.Username).First(&temp)
	if (temp != User{}) {
		c.JSON(202, "该用户已存在")
		return
	}

	db.Table("account").Where("email = ?", user.Email).First(&temp)
	if (temp != User{}) {
		c.JSON(202, "该邮箱已注册")
		return
	}

	hashedpassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(202, "密码加密失败：")
		return
	}
	user.Password = string(hashedpassword)

	err = db.Table("account").Create(&user).Error
	if err != nil {
		c.JSON(202, "注册用户失败")
		return
	}

	c.JSON(200, "成功新建用户")

}

func delete(c *gin.Context) {
	db, err := gorm.Open(mysql.Open("root:123456@tcp(localhost:3306)/gobase"), &gorm.Config{})
	if err != nil {
		c.JSON(202, "连接数据库失败")
		return
	}

	var user User
	err = c.Bind(&user)
	if err != nil {
		c.JSON(202, "err")
		return
	}

	if user.Username == "" {
		c.JSON(202, "请输入用户名")
		return
	}

	var temp User
	db.Table("account").Where("username = ?", user.Username).First(&temp)
	if (temp == User{}) {
		c.JSON(202, "该用户未注册")
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(temp.Password), []byte(user.Password))
	if err != nil {
		c.JSON(202, "密码错误")
		return
	}

	err = db.Table("account").Delete(&temp).Error
	if err != nil {
		c.JSON(202, "删除用户失败")
		return
	}

	c.JSON(200, "成功删除用户")
}

func login(c *gin.Context) {
	db, err := gorm.Open(mysql.Open("root:123456@tcp(localhost:3306)/gobase"), &gorm.Config{})
	if err != nil {
		c.JSON(202, "连接数据库失败")
		return
	}

	var user User
	err = c.ShouldBindJSON(&user)
	if err != nil {
		c.JSON(202, "err")
		return
	}

	if user.Username == "" {
		c.JSON(202, "请输入用户名")
		return
	}

	var temp User
	db.Table("account").Where("username = ?", user.Username).First(&temp)
	if (temp == User{}) {
		c.JSON(202, "该用户未注册")
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(temp.Password), []byte(user.Password))
	if err != nil {
		c.JSON(202, "密码错误")
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": user.Username,
		"email":    user.Email,
		"password": user.Password,
		"Time":     time.Now().Unix() + validtime,
	})

	tokenstring, err := token.SignedString(key)
	if err != nil {
		c.JSON(202, "cookie生成失败")
		return
	}

	c.SetCookie("token", tokenstring, int(validtime), "/", "", false, true)
	c.JSON(200, "登陆成功")
}

func logout(c *gin.Context) {
	c.SetCookie("token", "logout", 0, "/", "", false, true)
	c.JSON(200, "退出登陆")
}

func update(c *gin.Context) {
	tokenstring, err := c.Cookie("token")
	if err != nil {
		c.JSON(202, "尚未登陆")
		return
	}

	token, err := jwt.Parse(tokenstring, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	})
	if err != nil {
		c.JSON(202, "身份验证失败，请重新登陆")
		return
	}
	claims := token.Claims.(jwt.MapClaims)

	endtime := int64(claims["Time"].(float64))
	now := time.Now().Unix()
	if endtime < now {
		c.JSON(202, "登陆过期")
		return
	}

	var user User
	err = c.Bind(&user)
	if err != nil {
		c.JSON(202, "err")
		return
	}
	user.Username = claims["username"].(string)

	db, err := gorm.Open(mysql.Open("root:123456@tcp(localhost:3306)/gobase"), &gorm.Config{})
	if err != nil {
		c.JSON(202, "连接数据库失败")
		return
	}

	var temp User
	db.Table("account").Where("username = ?", user.Username).First(&temp)
	if (temp == User{}) {
		c.JSON(202, "该用户未注册")
		return
	}

	hashedpassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(202, "密码加密失败：")
		return
	}
	temp.Password = string(hashedpassword)

	result := db.Table("account").Where("id = ?", temp.ID).Updates(temp)
	if result.Error != nil {
		c.JSON(202, "修改密码失败")
		return
	}
	c.JSON(200, "修改密码成功")
}

func showall(c *gin.Context) {
	tokenstring, err := c.Cookie("token")
	if err != nil {
		c.JSON(202, "尚未登陆")
		return
	}

	token, err := jwt.Parse(tokenstring, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	})
	if err != nil {
		c.JSON(202, "身份验证失败，请重新登陆")
		return
	}
	claims := token.Claims.(jwt.MapClaims)

	endtime := int64(claims["Time"].(float64))
	now := time.Now().Unix()
	if endtime < now {
		c.JSON(202, "登陆过期")
		return
	}

	db, err := gorm.Open(mysql.Open("root:123456@tcp(localhost:3306)/gobase"), &gorm.Config{})
	if err != nil {
		c.JSON(202, "连接数据库失败")
		return
	}

	var users []User
	result := db.Table("account").Find(&users)
	if result.Error != nil {
		c.JSON(202, "查询数据库失败")
		return
	}

	for i := 0; i < len(users); i++ {
		users[i].Password = ""
	}

	c.JSON(200, users)

}
