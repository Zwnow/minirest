package handlers

import (
	"fmt"
	"os"

	"github.com/mailjet/mailjet-apiv3-go/v4"
)

func SendRegistrationMail(toEmail, toName string) error {
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
	_, err := mj.SendMailV31(&messages)
	if err != nil {
		return fmt.Errorf("could not send email: %w", err)
	}

	fmt.Printf("Registration Mail sent successfully to: %s\n", toEmail)
	return nil
}
