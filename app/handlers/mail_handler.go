package handlers

import (
	"fmt"
	"log"

	"github.com/mailjet/mailjet-apiv3-go/v4"
	"restfulapi/app/models"
	"restfulapi/config"
)

func SendRegistrationMail(cfg config.Config, toEmail, toName, verificationCode string) error {
	shouldSend := cfg.Mailjet.Active
	if shouldSend == "false" {
		return nil
	}

	verificationUrl := cfg.General.BaseURL + "/verify/" + verificationCode
	textBody := fmt.Sprintf("Hi! Please verify your E-Mail Address by clicking the following link: %s", verificationUrl)
	htmlBody := fmt.Sprintf(`
        <h3>Hi!</h3>
        <p>Thank you for registering to our app! Please verify your E-Mail Address by clicking on the following link: %s</p>
    `, verificationUrl)

	log.Printf("Using Mailjet key: %s, secret length: %d\n", cfg.Mailjet.Key, len(cfg.Mailjet.Secret))
	mj := mailjet.NewMailjetClient(cfg.Mailjet.Key, cfg.Mailjet.Secret)

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

func SendPasswordResetMail(cfg config.Config, user models.User, token models.PasswordResetToken) error {
	shouldSend := cfg.Mailjet.Active
	if shouldSend == "false" {
		return nil
	}

	resetUrl := cfg.General.BaseURL + "/password-reset/" + token.PasswordResetCode
	textBody := fmt.Sprintf("Hi! A password reset was requested for your account. Please follow this link to reset your password: %s", resetUrl)
	htmlBody := fmt.Sprintf(`
        <h3>Hi!</h3>
        <p>A password reset was requested for your account. Please follow this link to reset your password: %s</p>
    `, resetUrl)

	log.Printf("Using Mailjet key: %s, secret length: %d\n", cfg.Mailjet.Key, len(cfg.Mailjet.Secret))
	mj := mailjet.NewMailjetClient(cfg.Mailjet.Key, cfg.Mailjet.Secret)

	messageInfo := []mailjet.InfoMessagesV31{
		{
			From: &mailjet.RecipientV31{
				Email: "info@svot.app",
				Name:  "Sven-Ole Timm",
			},
			To: &mailjet.RecipientsV31{
				{
					Email: user.Email,
					Name:  user.Email,
				},
			},
			Subject:  "Password Reset",
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

	fmt.Printf("Registration Mail sent successfully to: %s\n", user.Email)
	return nil
}
