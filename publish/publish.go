package publish

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cloud.google.com/go/pubsub"
	"google.golang.org/api/iterator"
)

const baseURL = "https://europe-north1-pubsub.googleapis.com/v1"
const pubsubScope = "https://www.googleapis.com/auth/pubsub"

type pubsubPullRequest struct {
	MaxMessages int `json:"maxMessages"`
}

type accessTokenResponse struct {
	AccessToken string `json:"access_token"`
}
type pubsubMessages struct {
	Messages []pubsubMessage `json:"messages"`
}
type PullResponse struct {
	ReceivedMessages []pubsubReceivedMessage `json:"receivedMessages"`
}

type pubsubReceivedMessage struct {
	AckID           string        `json:"ackId"`
	Message         pubsubMessage `json:"message"`
	DeliveryAttempt int           `json:"deliveryAttempt"`
}

type acknowledgeRequest struct {
	AckIDs []string `json:"ackIds"`
}

type pubsubMessage struct {
	Data        string            `json:"data"`
	Attributes  map[string]string `json:"attributes,omitempty"`
	MessageID   string            `json:"messageId,omitempty"`
	PublishTime string            `json:"publishTime,omitempty"`
	OrderingKey string            `json:"orderingKey,omitempty"`
}

type PublishResponse struct {
	MessageIDs []string `json:"messageIds"`
}
type Credential struct {
	PrivateKey  string `json:"private_key"`
	ClientEmail string `json:"client_email"`
	ProjectID   string `json:"project_id"`
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

func trimEqualSuffix(str string) string {
	return strings.TrimRight(str, "=")
}

type jwtClaim struct {
	ISS   string `json:"iss"`
	Scope string `json:"scope"`
	Aud   string `json:"aud"`
	Exp   int64  `json:"exp"`
	Iat   int64  `json:"iat"`
}

func PublishThatScales(w io.Writer, projectID, topicID string, n int) error {
	projectID = "cr-lab-hraizada-2906225331"
	// topicID := "my-topic"
	ctx := context.Background()
	client, err := pubsub.NewClient(ctx, projectID)
	if err != nil {
		fmt.Println(err)
		return fmt.Errorf("pubsub.NewClient: %v", err)
	}
	fmt.Println("Listing all topics from the project:")
	topics, err := list(client)
	if err != nil {
		log.Fatalf("Failed to list topics: %v", err)
	}
	for _, t := range topics {
		fmt.Println(t)
	}
	defer client.Close()

	var wg sync.WaitGroup
	var totalErrors uint64
	t := client.Topic(topicID)

	for i := 0; i < n; i++ {
		result := t.Publish(ctx, &pubsub.Message{
			Data: []byte("Message " + strconv.Itoa(i)),
		})

		wg.Add(1)
		go func(i int, res *pubsub.PublishResult) {
			defer wg.Done()
			// The Get method blocks until a server-generated ID or
			// an error is returned for the published message.
			id, err := res.Get(ctx)
			if err != nil {
				// Error handling code can be added here.
				fmt.Println(err)
				fmt.Fprintf(w, "Failed to publish: %v", err)
				atomic.AddUint64(&totalErrors, 1)
				return
			}
			fmt.Println("successss")
			fmt.Fprintf(w, "Published message %d; msg ID: %v\n", i, id)
		}(i, result)
	}

	wg.Wait()

	if totalErrors > 0 {
		return fmt.Errorf("%d of %d messages did not publish successfully", totalErrors, n)
	}
	return nil
}
func list(client *pubsub.Client) ([]*pubsub.Topic, error) {
	ctx := context.Background()
	var topics []*pubsub.Topic
	it := client.Topics(ctx)
	for {
		topic, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		topics = append(topics, topic)
	}
	return topics, nil
}
func Publish(w io.Writer, projectID, topicID, msg string) error {
	ctx := context.Background()
	client, err := pubsub.NewClient(ctx, projectID)
	if err != nil {
		fmt.Println("error1", err)
		return fmt.Errorf("pubsub: NewClient: %v", err)
	}

	// l := client.Topics(ctx)
	// topicName, err := l.Next()
	// if err != nil {
	// 	fmt.Println(err)
	// }
	// fmt.Println(topicName)

	defer client.Close()

	t := client.Topic("my-topic")
	exists, err := t.Exists(ctx)
	if err != nil {
		fmt.Println("error222", err)
	}
	if !exists {
		t, err = client.CreateTopic(ctx, "my-topic")
		if err != nil {
			fmt.Println("Failed to create topic: %v", err)
		}
	}
	fmt.Println("existss", exists)

	result := t.Publish(ctx, &pubsub.Message{
		Data: []byte(msg),
	})
	// Block until the result is returned and a server-generated
	// ID is returned for the published message.
	//ctx, _ = context.WithTimeout(context.Background(), 20*time.Second)

	id, err := result.Get(ctx)
	if err != nil {
		fmt.Println("error2", err)
		return fmt.Errorf("pubsub: result.Get: %v", err)
	}
	fmt.Println(w, "Published a message; msg ID: %v\n", id)
	fmt.Fprintf(w, "Published a message; msg ID: %v\n", id)
	return nil
}
func NewCredential(r io.Reader) (*Credential, error) {
	var credential Credential
	err := json.NewDecoder(r).Decode(&credential)
	if err != nil {
		return nil, fmt.Errorf("failed to decode json: %w", err)
	}

	return &credential, nil
}

func PublishMessages(sb string) int {

	f, err := os.Open("/usr/bin/serviceaccount.json")
	if err != nil {
		fmt.Println("failed to open ", err)
		return 1
	}
	fmt.Println("new beg")
	cred, err := NewCredential(f)
	if err != nil {
		fmt.Println("new credentialssss", err)
		fmt.Printf("error: %v", err)
		return 1
	}
	fmt.Println("new beg2")
	var attrs map[string]string
	attribute := `{"name": "Tom"}`
	tmp := make(map[string]string)
	if err := json.Unmarshal([]byte(attribute), &tmp); err == nil {
		attrs = tmp
	}
	fmt.Println("new beg4")
	res, err := PublishString(cred, "test-topic", sb, attrs)
	if err != nil {
		fmt.Println(err)
		return 1
	}

	fmt.Println("send message ID=%s\n", res.MessageIDs[0])
	return 0
}
func (c *Credential) toAssertion() (string, error) {
	header := jwtHeader{
		Alg: "RS256",
		Typ: "JWT",
	}

	headerB, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}

	now := time.Now()
	claim := jwtClaim{
		ISS:   c.ClientEmail,
		Scope: pubsubScope,
		Aud:   "https://www.googleapis.com/oauth2/v4/token",
		Exp:   now.Unix() + 3600,
		Iat:   now.Unix(),
	}

	claimB, err := json.Marshal(claim)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claim: %w", err)
	}

	headerStr := base64.URLEncoding.EncodeToString(headerB)
	claimStr := base64.URLEncoding.EncodeToString(claimB)

	requestBody := trimEqualSuffix(headerStr) + "." + trimEqualSuffix(claimStr)

	block, _ := pem.Decode([]byte(c.PrivateKey))
	if block == nil {
		return "", fmt.Errorf("failed to decode private key: %w", err)
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("invalid private key")
	}

	hasher := crypto.SHA256.New()
	hasher.Write([]byte(requestBody))

	sigByte, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hasher.Sum(nil))
	if err != nil {
		return "", fmt.Errorf("failed to encrypt: %w", err)
	}

	signature := base64.URLEncoding.EncodeToString(sigByte)
	assertion := requestBody + "." + trimEqualSuffix(signature)
	return assertion, nil
}
func getAccessToken(c *Credential) (string, error) {
	assertion, err := c.toAssertion()
	if err != nil {
		return "", err
	}

	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	data.Set("assertion", assertion)

	r := strings.NewReader(data.Encode())

	client := &http.Client{}
	baseURL := "https://www.googleapis.com/oauth2/v4/token"
	req, err := http.NewRequest("POST", baseURL, r)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := client.Do(req)
	if err != nil {
		return "", nil
	}
	defer res.Body.Close()

	var tokenRes accessTokenResponse
	if err := json.NewDecoder(res.Body).Decode(&tokenRes); err != nil {
		return "", err
	}

	return tokenRes.AccessToken, nil
}
func PublishString(cred *Credential, topic string, str string, attrs map[string]string) (*PublishResponse, error) {
	token, err := getAccessToken(cred)
	if err != nil {
		return nil, err
	}
	fmt.Println("new beg8999", cred.ProjectID, baseURL, topic)
	endPoint := fmt.Sprintf("%s/projects/%s/topics/%s:publish", baseURL, cred.ProjectID, topic)
	fmt.Println("end", endPoint)
	msg := base64.StdEncoding.EncodeToString([]byte(str))
	fmt.Println("endw", msg)
	messages := pubsubMessages{
		Messages: []pubsubMessage{
			{
				Data:       msg,
				Attributes: attrs,
			},
		},
	}
	fmt.Println("endw123", messages)
	bs, err := json.Marshal(&messages)
	fmt.Println("endw122728", err)
	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(bs)

	client := &http.Client{}
	req, err := http.NewRequest("POST", endPoint, r)
	if err != nil {
		return nil, err
	}
	fmt.Println("token", token)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json; charset=utf-8")
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	fmt.Println("endlast", res)
	var pubRes PublishResponse
	if err := json.NewDecoder(res.Body).Decode(&pubRes); err != nil {
		return nil, err
	}

	return &pubRes, nil
}
func PullMessagesList() int {
	// if subscription == "" || accountJSON == "" {
	// 	fmt.Println("++" + subscription)
	// 	fmt.Println("++" + accountJSON)
	// 	fmt.Printf("Usage: subscriber -sub=sub_name -account=service_account.json")
	// 	return 1
	// }

	f, err := os.Open("/usr/bin/serviceaccount.json")
	if err != nil {
		fmt.Printf("failed to open ", err)
		return 1
	}

	cred, err := NewCredential(f)
	if err != nil {
		fmt.Printf("error: %v", err)
		return 1
	}

	res, err := PullMessages(cred, "new-sub", 1, true)
	if err != nil {
		fmt.Println(err)
		return 1
	}
	fmt.Println("messages", res)
	for _, msg := range res.ReceivedMessages {
		if msg.Message.Attributes == nil {
			fmt.Printf("MessageID: %s, Data: %s\n", msg.Message.MessageID, msg.Message.Data)
		} else {
			fmt.Printf("MessageID: %s, Data: %s, Attrs: %v\n", msg.Message.MessageID, msg.Message.Data, msg.Message.Attributes)
		}
	}

	return 0
}
func PullMessages(cred *Credential, subscription string, count int, acknowledge bool) (*PullResponse, error) {
	token, err := getAccessToken(cred)
	if err != nil {
		return nil, err
	}

	endPoint := fmt.Sprintf("%s/projects/%s/subscriptions/%s:pull", baseURL, cred.ProjectID, subscription)

	pubsubReq := pubsubPullRequest{
		MaxMessages: count,
	}

	bs, err := json.Marshal(&pubsubReq)
	if err != nil {
		return nil, err
	}
	r := bytes.NewReader(bs)

	client := &http.Client{}
	req, err := http.NewRequest("POST", endPoint, r)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json; charset=utf-8")
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return nil, fmt.Errorf("got error response")
	}

	var pullRes PullResponse
	if err := json.NewDecoder(res.Body).Decode(&pullRes); err != nil {
		return nil, err
	}

	var ackIDs []string
	for i := range pullRes.ReceivedMessages {
		ackIDs = append(ackIDs, pullRes.ReceivedMessages[i].AckID)

		b, err := base64.StdEncoding.DecodeString(pullRes.ReceivedMessages[i].Message.Data)
		if err != nil {
			return nil, err
		}

		pullRes.ReceivedMessages[i].Message.Data = string(b)
	}

	if acknowledge {
		if err := sendAcknowledge(cred.ProjectID, subscription, token, ackIDs); err != nil {
			return nil, err
		}
	}

	return &pullRes, nil
}
func sendAcknowledge(projectID string, subscription string, accessToken string, ackIDs []string) error {
	endPoint := fmt.Sprintf("%s/projects/%s/subscriptions/%s:acknowledge", baseURL, projectID, subscription)

	ackReq := acknowledgeRequest{
		ackIDs,
	}

	bs, err := json.Marshal(&ackReq)
	if err != nil {
		return err
	}
	r := bytes.NewReader(bs)

	client := &http.Client{}
	req, err := http.NewRequest("POST", endPoint, r)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json; charset=utf-8")
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	fmt.Println("acknowledged", res.StatusCode)
	if res.StatusCode != 200 {
		bs, _ := ioutil.ReadAll(res.Body)
		return fmt.Errorf("got error response: %s", string(bs))
	}

	return nil
}
