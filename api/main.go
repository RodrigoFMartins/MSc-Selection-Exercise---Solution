package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"exercise-backend/config"
	mysql "exercise-backend/infrastructure/db_mysql"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

var (
	failedLogins      = make(map[string]int)
	failedLoginsMux   sync.Mutex
	loginCooldown     = make(map[string]time.Time)
	loginCooldownMux  sync.Mutex
	loginCooldownTime = 30 * time.Second
	maxFailedAttempts = 3
)

var secretKey string

type App struct{}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func run() (err error) {
	generateSecretKey(32)
	if err != nil {
		fmt.Println("Error generating secret key:", err)
		return
	}
	// Load config
	if err = config.LoadConfig(); err != nil {
		return
	}
	// Handle Repository
	switch config.Conf.Repository {
	case "mysql":
		_, err = mysql.GetMysqlConn()
		if err != nil {
			return
		}
	default:
		log.Fatal("invalid repository")
	}
	app := App{}
	return app.Start()
}

func (a *App) Start() (err error) {
	r := mux.NewRouter()
	r.HandleFunc("/api/login", loginUser).Methods("POST")
	r.HandleFunc("/api/create", authenticateMiddleware(createPerson)).Methods("POST")
	r.HandleFunc("/api/user/{id}", authenticateMiddleware(getPerson)).Methods("GET")
	log.Fatal(http.ListenAndServe(":9090", r))
	return
}

func loginUser(w http.ResponseWriter, r *http.Request) {
	log.Print("Request received to LOGIN")
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Access the values from the Credentials struct
	username := creds.Username
	password := creds.Password

	loginCooldownMux.Lock()
	cooldownTime, cooldownExists := loginCooldown[username]
	loginCooldownMux.Unlock()

	if cooldownExists && time.Now().Before(cooldownTime) {
		remainingTime := cooldownTime.Sub(time.Now())
		http.Error(w, fmt.Sprintf("Too many login attempts. Please wait %s before trying again.", remainingTime), http.StatusTooManyRequests)
		return
	}

	// Validate credentials against stored data
	isAuth, ir := mysql.VerifyCredentials(username, password)
	log.Print(ir, isAuth)

	if isAuth && ir == nil {
		resetLoginAttempts(username) // Reset login attempts upon successful login

		log.Print("autenticado")
		idUse, irra := mysql.GetIDbyUserName(username)
		if irra != nil {
			return
		}
		claims := &Claims{
			Username: strconv.Itoa(idUse),
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: time.Now().Add(time.Minute * 30).Unix(), // Token expires in 30 mins
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

		// Sign the token with a secret key
		tokenString, err := token.SignedString([]byte(secretKey))
		if err != nil {
			log.Print("Error generating JWT token:", err)
			http.Error(w, "Error generating JWT token", http.StatusInternalServerError)
			return
		}

		// Return the JWT token in the response
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
	} else {
		incrementLoginAttempts(username)

		failedLoginsMux.Lock()
		attempts := failedLogins[username]
		failedLoginsMux.Unlock()

		if attempts >= maxFailedAttempts {
			startLoginCooldown(username)
			http.Error(w, fmt.Sprintf("Too many login attempts. Please wait %s before trying again.", loginCooldownTime), http.StatusTooManyRequests)
			return
		}

		// Set the status code to 403 Forbidden
		w.WriteHeader(http.StatusForbidden)

		// Write a response body
		fmt.Fprint(w, "403 Forbidden - Access Denied")
	}
}

func incrementLoginAttempts(username string) {
	failedLoginsMux.Lock()
	failedLogins[username]++
	failedLoginsMux.Unlock()
}

func resetLoginAttempts(username string) {
	failedLoginsMux.Lock()
	delete(failedLogins, username)
	failedLoginsMux.Unlock()
}

func startLoginCooldown(username string) {
	go func() {
		loginCooldownMux.Lock()
		loginCooldown[username] = time.Now().Add(loginCooldownTime)
		loginCooldownMux.Unlock()

		time.Sleep(loginCooldownTime)

		loginCooldownMux.Lock()
		delete(loginCooldown, username)
		loginCooldownMux.Unlock()
	}()
}

func generateSecretKey(length int) error {
	key := make([]byte, length)
	_, err := rand.Read(key)
	if err != nil {
		return err
	}

	// Encode the key to a base64 string
	encodedKey := base64.URLEncoding.EncodeToString(key)

	secretKey = encodedKey
	return nil
}

func getPerson(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr := vars["id"]
	persn, err := mysql.GetDatabyID(idStr)
	if err != nil {
		log.Print("User Does Not Exist!")
		// Set the status code to 403 Forbidden
		w.WriteHeader(http.StatusForbidden)

		// Write a response body
		fmt.Fprint(w, "404 Page Not Found")
	}
	arr := mysql.PersonToString(persn)
	// Generate the HTML list
	listHTML := "<ul>"
	for _, item := range arr {
		listHTML += "<li>" + item + "</li>"
	}
	listHTML += "</ul>"

	// Set the Content-Type header to HTML
	w.Header().Set("Content-Type", "text/html")

	// Write the list HTML to the response
	fmt.Fprint(w, listHTML)
}

func createPerson(w http.ResponseWriter, r *http.Request) {
	// Retrieve the username from the request context
	idUserSender := r.Context().Value("username").(string)
	// Read the request body
	var data map[string]interface{}
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Extract the keys and values as alternating elements in an array of strings
	var result []string
	for key, value := range data {
		result = append(result, key, fmt.Sprintf("%v", value))
	}

	// Print the array of key-value pairs
	fmt.Println(result)

	count1 := 0
	count2 := 0

	for _, element := range result {
		if element == "Username" && count1 == 0 {
			count1++
		} else if element == "Password" && count2 == 0 {
			count2++
		}
	}
	if count1 != 1 || count2 != 1 {
		http.Error(w, "Needs to give atleast Username and Password!", http.StatusBadRequest)
		return
	}
	log.Print(idUserSender)
	errr := mysql.CreatePersonFromData(result)
	if errr != nil {
		http.Error(w, "Username already exists!", http.StatusBadRequest)
		return
	} else {
		// Set the content type header to indicate that the response contains HTML
		w.Header().Set("Content-Type", "text/html")

		// Write the HTML success message to the response body
		successMsg := "<h1>Success!</h1><p>Your operation was successful.</p>"
		fmt.Fprint(w, successMsg)
	}
	//fmt.Fprintf(w, "Username: %s", idUserSender)
}

func authenticateMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get the JWT token from the Authorization header
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		log.Print(tokenString)

		// Split the Authorization header value to get the token
		authHeaderParts := strings.Split(tokenString, " ")
		if len(authHeaderParts) != 2 || authHeaderParts[0] != "Bearer" {
			http.Error(w, "Invalid token", http.StatusBadRequest)
			return
		}

		tokenString2 := authHeaderParts[1]

		// Parse the JWT token
		token, err := jwt.ParseWithClaims(tokenString2, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(secretKey), nil
		})
		if err != nil {
			http.Error(w, "Invalid token", http.StatusBadRequest)
			return
		}

		// Validate the token
		claims, ok := token.Claims.(*Claims)
		if !ok || !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Set the username from the claims in the request context
		ctx := context.WithValue(r.Context(), "username", claims.Username)
		r = r.WithContext(ctx)

		// Call the next handler
		next(w, r)
	}
}
