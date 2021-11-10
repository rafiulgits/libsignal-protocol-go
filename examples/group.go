package examples

import (
	"encoding/base64"
	"log"

	"github.com/RadicalApp/libsignal-protocol-go/groups"
	"github.com/RadicalApp/libsignal-protocol-go/keys/prekey"
	"github.com/RadicalApp/libsignal-protocol-go/protocol"
	"github.com/RadicalApp/libsignal-protocol-go/serialize"
	"github.com/RadicalApp/libsignal-protocol-go/session"
)

func GroupSession() {

	// Create a serializer object that will be used to encode/decode data.
	serializer := newSerializer()

	// Create our users who will talk to each other.
	alice := newUser("Alice", 1, serializer)
	bob := newUser("Bob", 2, serializer)
	groupName := "123"

	// ***** Build one-to-one session with group members *****

	// Create a session builder to create a session between Alice -> Bob.
	alice.buildSession(bob.address, serializer)
	bob.buildSession(alice.address, serializer)

	// Create a PreKeyBundle from Bob's prekey records and other
	// data.
	log.Println("Alice ---> Bob")
	log.Println("Fetching Bob's prekey with ID: ", bob.preKeys[0].ID())
	retrivedPreKey := prekey.NewBundle(
		bob.registrationID,
		bob.deviceID,
		bob.preKeys[0].ID(),
		bob.signedPreKey.ID(),
		bob.preKeys[0].KeyPair().PublicKey(),
		bob.signedPreKey.KeyPair().PublicKey(),
		bob.signedPreKey.Signature(),
		bob.identityKeyPair.PublicKey(),
	)

	// Process Bob's retrieved prekey to establish a session.
	log.Println("Building sender's (Alice) session...")
	err := alice.sessionBuilder.ProcessBundle(retrivedPreKey)
	if err != nil {
		log.Fatalln("Unable to process retrieved prekey bundle")
	}

	// Create a session builder to create a session between Alice -> Bob.
	aliceSenderKeyName := protocol.NewSenderKeyName(groupName, alice.address)
	aliceSkdm, err := alice.groupBuilder.Create(aliceSenderKeyName)
	if err != nil {
		log.Fatalln("Unable to create group session")
	}
	aliceSendingCipher := groups.NewGroupCipher(alice.groupBuilder, aliceSenderKeyName, alice.senderKeyStore)

	// Create a one-to-one session cipher to encrypt the skdm to Bob.
	aliceBobSessionCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	encryptedSkdm, err := aliceBobSessionCipher.Encrypt(aliceSkdm.Serialize())
	if err != nil {
		log.Fatalln("Unable to encrypt message: ", err)
	}

	// ***** Bob receive senderkey distribution message from Alice *****

	// Emulate receiving the message as JSON over the network.
	log.Println("Building message from bytes on Bob's end.")
	receivedMessage, err := protocol.NewPreKeySignalMessageFromBytes(encryptedSkdm.Serialize(), serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		log.Fatalln("Unable to emulate receiving message as JSON: ", err)
	}

	// Try and decrypt the senderkey distribution message
	bobAliceSessionCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	msg, err := bobAliceSessionCipher.DecryptMessage(receivedMessage)
	if err != nil {
		log.Fatalln("Unable to decrypt message: ", err)
	}
	bobReceivedSkdm, err := protocol.NewSenderKeyDistributionMessageFromBytes(msg, serializer.SenderKeyDistributionMessage)
	if err != nil {
		log.Fatalln("Unable to create senderkey distribution message from bytes: ", err)
	}

	// ***** Alice Send *****

	// Encrypt some messages to send with Alice's group cipher
	log.Println("Alice sending messages to Bob...")
	alicePlainMessages, aliceEncryptedMessages := sendGroupMessages(1, aliceSendingCipher, serializer)

	// Build bob's side of the session.
	bob.groupBuilder.Process(aliceSenderKeyName, bobReceivedSkdm)
	receivingBobCipher := groups.NewGroupCipher(bob.groupBuilder, aliceSenderKeyName, bob.senderKeyStore)

	// Decrypt the messages sent by alice.
	log.Println("Bob receiving messages from Alice...")
	receiveGroupMessages(aliceEncryptedMessages, alicePlainMessages, receivingBobCipher)

	// ***** Bob send senderkey distribution message to Alice *****

	// Create a group builder with Bob's address.
	bobSenderKeyName := protocol.NewSenderKeyName(groupName, bob.address)
	bobSkdm, err := bob.groupBuilder.Create(bobSenderKeyName)
	if err != nil {
		log.Fatalln("Unable to create group session")
	}
	bobSendingCipher := groups.NewGroupCipher(bob.groupBuilder, bobSenderKeyName, bob.senderKeyStore)

	// Encrypt the senderKey distribution message to send to Alice.
	bobEncryptedSkdm, err := bobAliceSessionCipher.Encrypt(bobSkdm.Serialize())
	if err != nil {
		log.Fatalln("Unable to encrypt message: ", err)
	}

	// Emulate receiving the message as JSON over the network.
	log.Println("Building message from bytes on Alice's end.")
	aliceReceivedMessage, err := protocol.NewSignalMessageFromBytes(bobEncryptedSkdm.Serialize(), serializer.SignalMessage)
	if err != nil {
		log.Fatalln("Unable to emulate receiving message as JSON: ", err)
	}

	// ***** Alice receives senderkey distribution message from Bob *****

	// Decrypt the received message.
	msg, err = aliceBobSessionCipher.Decrypt(aliceReceivedMessage)
	if err != nil {
		log.Fatalln("Unable to decrypt message: ", err)
	}
	aliceReceivedSkdm, err := protocol.NewSenderKeyDistributionMessageFromBytes(msg, serializer.SenderKeyDistributionMessage)
	if err != nil {
		log.Fatalln("Unable to create senderkey distribution message from bytes: ", err)
	}

	// ***** Bob Send *****

	// Encrypt some messages to send with Bob's group cipher
	log.Println("Bob sending messages to Alice...")
	bobPlainMessages, bobEncryptedMessages := sendGroupMessages(1, bobSendingCipher, serializer)

	// Build alice's side of the session.
	alice.groupBuilder.Process(bobSenderKeyName, aliceReceivedSkdm)
	receivingAliceCipher := groups.NewGroupCipher(alice.groupBuilder, bobSenderKeyName, alice.senderKeyStore)

	// Decrypt the messages sent by bob.
	log.Println("Alice receiving messages from Bob...")
	receiveGroupMessages(bobEncryptedMessages, bobPlainMessages, receivingAliceCipher)
}

// sendGroupMessages will generate and return a list of plaintext and encrypted messages.
func sendGroupMessages(count int, cipher *groups.GroupCipher, serializer *serialize.Serializer) ([]string, []protocol.CiphertextMessage) {
	texts := []string{
		"Lorem ipsum dolor sit amet",
		"consectetur adipiscing elit",
		"sed do eiusmod tempor incididunt",
		"ut labore et dolore magna aliqua.",
	}
	messageStrings := make([]string, count)
	for i := 0; i < count; i++ {
		messageStrings[i] = texts[i%len(texts)]
	}

	messages := make([]protocol.CiphertextMessage, count)
	// Emulate receiving the message as JSON over the network.
	log.Println("Building message from bytes to emulate sending over the network.")
	for i, str := range messageStrings {
		msg := encryptGroupMessage(str, cipher, serializer)
		messages[i] = msg
	}

	return messageStrings, messages
}

// receiveMessages is a helper function to receive a bunch of encrypted messages and decrypt them.
func receiveGroupMessages(messages []protocol.CiphertextMessage, messageStrings []string, cipher *groups.GroupCipher) {
	for i, receivedMessage := range messages {
		msg := decryptGroupMessage(receivedMessage, cipher)
		if messageStrings[i] != msg {
			log.Fatalln("Decrypted message does not match original: ", messageStrings[i], " != ", msg)
		}
	}
}

// encryptMessage is a helper function to send encrypted messages with the given cipher.
func encryptGroupMessage(message string, cipher *groups.GroupCipher, serializer *serialize.Serializer) protocol.CiphertextMessage {
	plaintextMessage := []byte(message)
	log.Println("Encrypting message: ", string(plaintextMessage))
	encrypted, err := cipher.Encrypt(plaintextMessage)
	if err != nil {
		log.Fatalln("Unable to encrypt message: ", err)
	}
	log.Println("Encrypted message: ", base64.StdEncoding.EncodeToString([]byte(encrypted.Serialize())))

	var encryptedMessage protocol.CiphertextMessage
	switch encrypted.(type) {
	case *protocol.SenderKeyMessage:
		message := encrypted.(*protocol.SenderKeyMessage)
		encryptedMessage, err = protocol.NewSenderKeyMessageFromBytes(message.SignedSerialize(), serializer.SenderKeyMessage)
		if err != nil {
			log.Fatalln("Unable to emulate receiving message as JSON: ", err)
		}
	}

	return encryptedMessage
}

// decryptMessage is a helper function to decrypt messages of a session.
func decryptGroupMessage(message protocol.CiphertextMessage, cipher *groups.GroupCipher) string {
	senderKeyMessage := message.(*protocol.SenderKeyMessage)
	//if !ok {
	//	log.Fatalln("Wrong message type in decrypting group message.")
	//}

	msg, err := cipher.Decrypt(senderKeyMessage)
	if err != nil {
		log.Fatalln("Unable to decrypt message: ", err)
	}
	log.Println("Decrypted message: ", string(msg))

	return string(msg)
}
