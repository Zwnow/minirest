package main

func main() {
	/*
		err := godotenv.Load()
		if err != nil {
			log.Fatal("Error loading .env file")
		}

		publicKey := os.Getenv("MAILJET_KEY")
		secretKey := os.Getenv("MAILJET_SECRET")

		mj := mailjet.NewMailjetClient(publicKey, secretKey)

		messageInfo := []mailjet.InfoMessagesV31{
			{
				From: &mailjet.RecipientV31{
					Email: "info@svot.app",
					Name:  "Sven-Ole Timm",
				},
				To: &mailjet.RecipientsV31{
					mailjet.RecipientV31{
						Email: "sevenzeroarts@gmail.com",
						Name:  "Sven-O",
					},
				},
				Subject:  "Test Mail",
				TextPart: "This is a test e-mail, I am using this template while I am building my app.",
				HTMLPart: "<h3>This is a test e-mail</h3><p>I am using this template while I am building my app.</p>",
			},
		}

		messages := mailjet.MessagesV31{Info: messageInfo}
		res, err := mj.SendMailV31(&messages)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Data: %+v\n", res)
	*/
}
