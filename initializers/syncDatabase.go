package initializers

import "jwtauth/models"

func SyncDatabase() {
	DB.AutoMigrate(&models.User{})
}