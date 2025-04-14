package handlers

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/joho/godotenv"
	"github.com/mailjet/mailjet-apiv3-go/v4"
)

func loadEnv() error {
	dir, err := os.Getwd()
	if err != nil {
		log.Printf("Failed to get working directory: %v", err)
		return err
	}

	for {
		envPath := filepath.Join(dir, ".env")
		if _, err := os.Stat(envPath); err == nil {
			err := godotenv.Load(envPath)
			if err != nil {
				log.Printf("Error loading .env file: %v", err)
				return err
			}
			return nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return errors.New(".env file not found in any parent directory")
		}
		dir = parent
	}
}

func SendRegistrationMail(toEmail, toName string) error {
	err := loadEnv()
	if err != nil {
		return err
	}

	shouldSend := os.Getenv("MAIL_ACTIVE")
	if shouldSend == "false" {
		return nil
	}

	publicKey := os.Getenv("MAILJET_KEY")
	secretKey := os.Getenv("MAILJET_SECRET")

	verificationUrl := ""
	textBody := fmt.Sprintf("Hi! Please verify your E-Mail Address by clicking the following link: %s", verificationUrl)
	htmlBody := fmt.Sprintf(`
        <h3>Hi!</h3>
        <p>Thank you for registering to our app! Please verify your E-Mail Address by clicking on the following link: %s</p>
    `, verificationUrl)

	mj := mailjet.NewMailjetClient(publicKey, secretKey)

	messageInfo := []mailjet.InfoMessagesV31{
		{
			From: &mailjet.RecipientV31{
				Email: "info@svot.app",
				Name:  "Sven-Ole Timm",
			},
			To: &mailjet.RecipientsV31{
				{
					Email: toEmail,
					Name:  toName,
				},
			},
			Subject:  "Verify your E-Mail Address",
			TextPart: textBody,
			HTMLPart: htmlBody,
		},
	}

	messages := mailjet.MessagesV31{Info: messageInfo}
	// response, err
	_, err = mj.SendMailV31(&messages)
	if err != nil {
		return fmt.Errorf("could not send email: %w", err)
	}

	fmt.Printf("Registration Mail sent successfully to: %s\n", toEmail)
	return nil
}
