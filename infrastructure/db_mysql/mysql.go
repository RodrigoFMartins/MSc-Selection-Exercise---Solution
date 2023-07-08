package mysql

import (
	"errors"
	"exercise-backend/config"
	"fmt"
	"log"
	"strconv"
	"sync"

	"bitbucket.org/liamstask/goose/lib/goose"
	"github.com/jinzhu/gorm"
)

var lock = &sync.Mutex{}

var dbConn *gorm.DB

type Persons struct {
	ID       int    `gorm:"primary_key;auto_increment"`
	Name     string `gorm:"not null"`
	Age      int    `gorm:"not null"`
	Family   string `gorm:"not null"`
	Username string `gorm:"not null"`
	Password string `gorm:"not null"`
	Role     string `gorm:"not null"`
}

// GetMysqlConn returns mysql db connection.
// Ensures that only one connection exists (singleton pattern).
func GetMysqlConn() (db *gorm.DB, err error) {
	if dbConn == nil {
		lock.Lock()
		defer lock.Unlock()
		if dbConn == nil {
			return startDB()
		}
	}
	return dbConn, nil
}

// startDB creates DB connection and runs migrations
func startDB() (db *gorm.DB, err error) {
	// Initialize db connection
	db, err = gorm.Open("mysql", config.Conf.DBPath)
	if err != nil {
		log.Printf("database opening error: %v\n", err)
		return
	}

	db.DB().SetMaxOpenConns(1)
	log.Println("database connection established...")

	// Create migrations config
	migrateConf := &goose.DBConf{
		MigrationsDir: config.Conf.MigrationsPath,
		Env:           "development",
		Driver: goose.DBDriver{
			Name:    "mysql",
			OpenStr: config.Conf.DBPath,
			Import:  "github.com/go-sql-driver/mysql",
			Dialect: &goose.MySqlDialect{},
		},
	}

	if !db.HasTable(&Persons{}) {
		err = goose.RunMigrationsOnDb(migrateConf, migrateConf.MigrationsDir, 1, db.DB())
		if err != nil {
			log.Printf("running migrations error: %v\n", err)
			return
		}

		log.Println("Database migrated for the first time...")
	} else {
		// Get the latest migration
		var latest int64
		latest, err = goose.GetMostRecentDBVersion(migrateConf.MigrationsDir)
		if err != nil {
			log.Printf("getting latest migration error: %v\n", err)
			return
		}

		// Run migration
		err = goose.RunMigrationsOnDb(migrateConf, migrateConf.MigrationsDir, latest, db.DB())
		if err != nil {
			log.Printf("running migrations error: %v\n", err)
			return
		}
	}
	// Insert db connection into var and return
	dbConn = db
	return
}

func VerifyCredentials(username, password string) (bool, error) {
	db, err := GetMysqlConn()
	if err != nil {
		return false, err
	}
	log.Print(username)
	log.Print(password)
	user := Persons{}
	err = db.Where("username = ?", username).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, errors.New("invalid username or password")
		}
		return false, err
	}

	if user.Password != password {
		return false, errors.New("invalid username or password")
	}

	return true, err
}

func GetIDbyUserName(username string) (int, error) {
	db, err := GetMysqlConn()
	if err != nil {
		return 0, err
	}
	user := Persons{}
	err = db.Where("username = ?", username).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return 0, errors.New("invalid username or password")
		}
		return 0, err
	}

	return user.ID, err
}

func GetDatabyID(idUser string) (Persons, error) {
	db, err := GetMysqlConn()
	user := Persons{}
	if err != nil {
		return user, err
	}
	err = db.Where("ID = ?", idUser).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return user, errors.New("invalid ID")
		}
		return user, err
	}

	return user, err
}

func PersonToString(per Persons) []string {
	// Convert the Person struct to an array of strings
	return []string{per.Name, fmt.Sprintf("%d", per.Age), per.Family, per.Role}
}

func CreatePersonFromData(data []string) error {
	person := Persons{
		Role: "normal",
	}
	db, err := GetMysqlConn()
	for i := 0; i < len(data); i += 2 {
		key := data[i]
		value := data[i+1]

		switch key {
		case "Name":
			person.Name = value
		case "Age":
			age, err := strconv.Atoi(value)
			if err != nil {
				log.Printf("Invalid age value: %s", value)
				continue
			}
			person.Age = age
		case "Family":
			person.Family = value
		case "Username":
			boli, erri := UsernameExists(value)
			if !boli && erri == nil {
				person.Username = value
			} else {
				log.Print("username already exists")
				return errors.New("failed to query database")
			}

		case "Password":
			person.Password = value
		case "Role":
			person.Role = value
		default:
			log.Printf("Unknown key: %s", key)
		}
	}

	if err != nil {
		return err
	}

	err = db.Create(&person).Error
	if err != nil {
		log.Printf("failed to add person to database: %v\n", err)
		return errors.New("failed to add person to database")
	}
	return nil
}

func UsernameExists(username string) (bool, error) {
	db, err := GetMysqlConn()
	if err != nil {
		return false, err
	}

	// Query the database for the username
	var count int
	err = db.Model(&Persons{}).Where("username = ?", username).Count(&count).Error
	if err != nil {
		log.Printf("failed to query database: %v\n", err)
		return false, errors.New("failed to query database")
	}

	return count > 0, nil
}
