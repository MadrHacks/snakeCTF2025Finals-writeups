package main

import (
	"bufio"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
)

func main() {
	boardMap := make(map[string]int)

	for seed := 0; seed <= 10000; seed++ {
		board := hex.EncodeToString([]byte(toString(GenerateRandomBoard(seed))))
		boardMap[board] = seed
	}

	hostPtr := flag.String("host", "", "The server hostname or IP address to connect to (required).")
	portPtr := flag.Int("port", 0, "The port number to connect on (required).")
	sslPtr := flag.Bool("ssl", false, "Use SSL/TLS for the connection.")
	tokenPtr := flag.String("team_token", "", "Optional team authentication token.")
	flag.Parse()

	if *hostPtr == "" || *portPtr == 0 {
		fmt.Println("Error: The 'host' and 'port' flags are required.")
		fmt.Println("\nUsage:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	serverAddr := fmt.Sprintf("%v:%v", *hostPtr, *portPtr)

	var conn net.Conn
	var err error
	if *sslPtr {
		config := &tls.Config{
			InsecureSkipVerify: true,
		}
		conn, err = tls.Dial("tcp", serverAddr, config)
	} else {
		conn, err = net.Dial("tcp", serverAddr)
	}

	if err != nil {
		fmt.Println("Error connecting:", err)
		return
	}

	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {

		}
	}(conn)
	buff := bufio.NewReader(conn)

	if *tokenPtr != "" {
		buff.ReadString(':')
		fmt.Fprintln(conn, *tokenPtr)
	}

	password := ""

	for i := 0; i < 40; i++ {

		for i := 0; i <= 3; i++ {
			message, err := buff.ReadString('\n')
			if err != nil {
				return
			}
			fmt.Print(message)
		}

		message, _ := buff.ReadString('h')
		seed := boardMap[hex.EncodeToString([]byte(message))]

		fmt.Println("seed:", seed)

		gen := rand.New(rand.NewSource(int64(seed)))

		var board [8][8]int

		// 70% empty, 30% random pieces
		for i := 0; i < 8; i++ {
			for j := 0; j < 8; j++ {
				if gen.Float64() < 0.7 {
					board[i][j] = Empty
				} else {
					// Random piece between 1 and 12
					board[i][j] = gen.Intn(12) + 1
				}
			}
		}

		moves := GenerateMoves(board)
		correct := moves[gen.Intn(len(moves))]

		password += correct

		_, err = fmt.Fprintln(conn, correct)
		if err != nil {
			return
		}

	}

	for i := 0; i <= 4; i++ {
		_, err = buff.ReadString('\n')
		if err != nil {
			return
		}
	}

	_, err = fmt.Fprintln(conn, hex.EncodeToString(obfHash([]byte(password))))
	if err != nil {
		return
	}

	for i := 0; i <= 4; i++ {
		message, err := buff.ReadString('\n')
		if err != nil {
			return
		}
		fmt.Print("after: ", message)
	}

}
