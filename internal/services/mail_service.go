package services

import (
	"bytes"
	"fmt"
	"html/template"
	"os"

	"gopkg.in/gomail.v2"
	"gorm.io/gorm"
	"hnex.com/internal/utils"
)

// Declaration

type MailService struct {
	DB *gorm.DB
}

func NewMailService(db *gorm.DB) *MailService {
	return &MailService{DB: db}
}

// Code

func (s *MailService) SendEmail(to, subject, body string) error {
	user := os.Getenv("MAIL_USER")
	appPassword := os.Getenv("MAIL_APP_PASSWORD")

	m := gomail.NewMessage()
	m.SetHeader("From", user)
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	d := gomail.NewDialer("smtp.gmail.com", 587, user, appPassword)

	if err := d.DialAndSend(m); err != nil {
		return err
	}

	return nil
}

func (s *MailService) SendVerificationEmail(toEmail, displayName string) (string, error) {
	verificationCode := utils.GenVerificationCode(6)

	const emailTemplateHTML = `
<div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 20px auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px; background-color: #f9f9f9;">
    <div style="text-align: center; padding-bottom: 20px; border-bottom: 1px solid #eee;">
        <h2 style="color: #f54a00;">Hi {{.DisplayName}}!</h2>
    </div>
    <div style="padding: 20px 0;">
        <p>Thank you for registering your account. Please use the verification code below to complete your registration:</p>
        <div style="background-color: #ffd6a8; border: 1px solid #ff6900; padding: 15px; text-align: center; font-size: 24px; font-weight: bold; letter-spacing: 2px; border-radius: 5px; margin: 20px 0; color: #f54a00;">{{.VerificationCode}}</div>
        <p>This code will expire in a few minutes. If you did not request this code, please ignore this email.</p>
        <p>Sincerely,<br>Our Support Team</p>
    </div>
    <div style="text-align: center; font-size: 12px; color: #777; border-top: 1px solid #eee; padding-top: 20px; margin-top: 20px;">
        <p>&copy; 2025 HNEX.COM. All Rights Reserved.</p>
    </div>
</div>
`

	data := struct {
		DisplayName      string
		VerificationCode string
	}{
		DisplayName:      displayName,
		VerificationCode: verificationCode,
	}

	tmpl, err := template.New("email").Parse(emailTemplateHTML)
	if err != nil {
		return "", fmt.Errorf("failed to parse email template: %w", err)
	}

	var bodyBuffer bytes.Buffer
	if err := tmpl.Execute(&bodyBuffer, data); err != nil {
		return "", fmt.Errorf("failed to execute email template: %w", err)
	}

	subject := "Verify your email"
	err = s.SendEmail(toEmail, subject, bodyBuffer.String())
	if err != nil {
		return "", fmt.Errorf("failed to send verification email: %w", err)
	}

	return verificationCode, nil
}
