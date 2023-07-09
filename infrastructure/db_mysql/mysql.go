package mysql

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"exercise-backend/config"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"

	"bitbucket.org/liamstask/goose/lib/goose"
	"github.com/jinzhu/gorm"
	"golang.org/x/crypto/argon2"
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

	val, irr := comparePasswordHash(password, user.Password)
	if !val || irr != nil {
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

func GetRoleByID(idUser string) (string, error) {
	db, err := GetMysqlConn()
	user := Persons{}
	if err != nil {
		return "normal", err
	}
	err = db.Where("ID = ?", idUser).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "normal", errors.New("invalid ID")
		}
		return "normal", err
	}

	return user.Role, err
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
			/*
				passwrd, err1 := hashPassword(value)
				if err1 == nil {
					person.Password = passwrd
				} else {
					log.Print("password problem")
					return errors.New("password problem")
				}
			*/
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

const (
	// Define the parameters for the Argon2 hashing algorithm
	iterations  = 4
	memory      = 64 * 1024 // 64MB
	parallelism = 4
	saltSize    = 16
	keyLength   = 32
)

func hashPassword(password string) (string, error) {
	// Generate a random salt
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	// Hash the password using Argon2
	hash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, keyLength)

	// Encode the salt and hashed password as a single string
	encodedSalt := base64.StdEncoding.EncodeToString(salt)
	encodedHash := base64.StdEncoding.EncodeToString(hash)
	encodedPassword := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, memory, iterations, parallelism, encodedSalt, encodedHash)

	return encodedPassword, nil
}

func comparePasswordHash(password, encodedPassword string) (bool, error) {
	if !strings.HasPrefix(encodedPassword, "$argon2id$") {
		return password == encodedPassword, nil
	}

	// Extract the parameters and encoded salt from the encoded password
	var version, m, t uint32
	var encodedSalt, encodedHash string
	var p uint8
	log.Print("aaaa", password, encodedPassword)
	n, err := fmt.Sscanf(encodedPassword, "$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", &version, &m, &t, &p, &encodedSalt, &encodedHash)

	log.Print(version)
	log.Print(m)
	log.Print(t)
	log.Print(p)
	log.Print(encodedSalt)
	log.Print(encodedHash)
	if err != nil {
		return false, err
	}
	log.Print(password, encodedPassword)
	// Check if all expected fields were successfully scanned
	if n != 6 {
		return false, errors.New("invalid encoded password format")
	}

	salt, err := base64.StdEncoding.DecodeString(encodedSalt)
	if err != nil {
		return false, err
	}

	hash, err := base64.StdEncoding.DecodeString(encodedHash)
	if err != nil {
		return false, err
	}

	// Hash the input password using the extracted salt and parameters
	comparisonHash := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(hash)))

	// Compare the generated hash with the stored hash using subtle.ConstantTimeCompare
	return subtle.ConstantTimeCompare(hash, comparisonHash) == 1, nil
}
