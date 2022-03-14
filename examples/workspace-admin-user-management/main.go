package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/option"
)

// Variables
var (
	userEmail = "user1@company.com" // SuperAdmin to be impersonated if superAdmin users are being managed.
	projectID = "projectID"         // Secret manager project for demo.

	// List of users(Ex: SuperAdmins) whose password will be rotated
	users = []string{
		"user1@company.com",
		"user2@company.com",
		"user3@company.com",
	}
)

// Directory object that impersonates the Admin API user
func DirectoryService(userEmail string) (*admin.Service, error) {

	SAkey, err := ioutil.ReadFile(os.Getenv("key_file"))
	if err != nil {
		log.Fatalf("Error reading key file: %v\n", err)
	}

	ctx := context.Background()

	config, err := google.JWTConfigFromJSON(SAkey, admin.AdminDirectoryUserScope)
	if err != nil {
		log.Fatalf("Error parsing for JWT config in the key: %v\n", err)
	}

	config.Subject = userEmail

	ts := config.TokenSource(ctx)
	srv, err := admin.NewService(ctx, option.WithTokenSource(ts))
	if err != nil {
		log.Fatalf("Error creating admin service: %v\n", err)
	}

	return srv, nil
}

// Generate random password
func generateRandomPassword() (password string) {

	const raw_letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqurstuvwxyz/!@#"

	buf := make([]byte, 32)
	for i := 0; i < 32; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(raw_letters))))
		if err != nil {
			log.Fatalf("Error generaing rand number, %v\n", err)
		}
		buf[i] = raw_letters[num.Int64()]
	}

	return string(buf)
}

// Workspace PATCH call to rotate user password
func rotateAdminPassword() {
	srv, err := DirectoryService(userEmail)
	if err != nil {
		log.Fatalf("Error creating DirectoryService for user: %q, err: %v\n", userEmail, err)
	}

	// Workspace UPDATE call
	for _, user := range users {

		secret := generateRandomPassword()

		r, err := srv.Users.Update(user,
			&admin.User{
				Password: secret,
			}).Do()
		if err != nil {
			log.Fatalf("Error making UPDATE API call: %v\n", err)
		}
		fmt.Printf("Credential rotated for (%s)\n", r.PrimaryEmail)

		// call the bash script to record secret in secret manager for demo.
		// This is where any third party secret manager API calls can be made. Ex: Vault or BeyondTrust on-prem.
		secretID := strings.Split(user, "@")

		// When run on Google CloudBuild "/workspace" is the persistent filesystem. Update the script path for local testing.
		args := fmt.Sprintf("/workspace/scripts/secret-manager.sh %q %q %q", secretID[0], projectID, secret)

		_, err = exec.Command("/bin/bash", "-c", args).Output()
		if err != nil {
			log.Fatalf("error executing bash script: %v\n", err)
		}
	}
}

func main() {
	// This method makes the workspace API call to rotate platform admin credentails.
	rotateAdminPassword()
}
