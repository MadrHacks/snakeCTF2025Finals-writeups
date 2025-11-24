package main

import (
	"fmt"
	"math/rand"
	"strings"
)

const (
	Empty       = 0
	WhitePawn   = 1
	WhiteRook   = 2
	WhiteKnight = 3
	WhiteBishop = 4
	WhiteQueen  = 5
	WhiteKing   = 6
	BlackPawn   = 7
	BlackRook   = 8
	BlackKnight = 9
	BlackBishop = 10
	BlackQueen  = 11
	BlackKing   = 12
)

var pieceSymbols = map[int]string{
	0:  "🞔",
	1:  "♙",
	2:  "♖",
	3:  "♘",
	4:  "♗",
	5:  "♕",
	6:  "♔",
	7:  "♟",
	8:  "♜",
	9:  "♞",
	10: "♝",
	11: "♛",
	12: "♚",
}

func GenerateRandomBoard(seed int) [8][8]int {
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
	return board
}

func toString(board [8][8]int) string {

	var sb strings.Builder

	for i := 0; i < 8; i++ {
		sb.WriteString(fmt.Sprintf("%d ", 8-i))
		for j := 0; j < 8; j++ {
			sb.WriteString(fmt.Sprintf(" %s", pieceSymbols[board[i][j]]))
		}
		sb.WriteString(fmt.Sprintf("\n"))
	}
	sb.WriteString(fmt.Sprintf("    a   b   c   d   e   f   g   h"))

	return sb.String()
}

func GenerateMoves(board [8][8]int) []string {
	var moves []string
	for r := 0; r < 8; r++ {
		for c := 0; c < 8; c++ {
			piece := board[r][c]
			if piece == Empty {
				continue
			}
			isWhite := piece >= WhitePawn && piece <= WhiteKing
			if !isWhite {
				continue
			}
			switch piece {
			case WhitePawn:
				moves = append(moves, pawnMoves(board, r, c, piece)...)
			case WhiteKnight:
				moves = append(moves, knightMoves(board, r, c, piece)...)
			case WhiteBishop:
				moves = append(moves, slidingMoves(board, r, c, piece, [][2]int{{1, 1}, {1, -1}, {-1, 1}, {-1, -1}})...)
			case WhiteRook:
				moves = append(moves, slidingMoves(board, r, c, piece, [][2]int{{1, 0}, {-1, 0}, {0, 1}, {0, -1}})...)
			case WhiteQueen:
				moves = append(moves, slidingMoves(board, r, c, piece, [][2]int{
					{1, 0}, {-1, 0}, {0, 1}, {0, -1},
					{1, 1}, {1, -1}, {-1, 1}, {-1, -1},
				})...)
			case WhiteKing:
				moves = append(moves, kingMoves(board, r, c, piece)...)
			}
		}
	}
	return moves
}

func pawnMoves(board [8][8]int, r, c, piece int) []string {
	var moves []string
	dir := -1
	if piece >= BlackPawn {
		dir = 1
	}
	startRow := 6
	if piece >= BlackPawn {
		startRow = 1
	}
	to := func(r, c int) string { return fmt.Sprintf("%c%d", 'a'+c, 8-r) }
	from := to(r, c)
	if inBounds(r+dir, c) && board[r+dir][c] == Empty {
		moves = append(moves, from+to(r+dir, c))
		if r == startRow && board[r+2*dir][c] == Empty {
			moves = append(moves, from+to(r+2*dir, c))
		}
	}
	for _, dc := range []int{-1, 1} {
		nr, nc := r+dir, c+dc
		if inBounds(nr, nc) && board[nr][nc] != Empty && isEnemy(piece, board[nr][nc]) {
			moves = append(moves, from+to(nr, nc))
		}
	}
	return moves
}

func knightMoves(board [8][8]int, r, c, piece int) []string {
	dirs := [][2]int{{2, 1}, {1, 2}, {-1, 2}, {-2, 1}, {-2, -1}, {-1, -2}, {1, -2}, {2, -1}}
	return jumpMoves(board, r, c, piece, dirs)
}

func kingMoves(board [8][8]int, r, c, piece int) []string {
	dirs := [][2]int{
		{1, 0}, {-1, 0}, {0, 1}, {0, -1},
		{1, 1}, {1, -1}, {-1, 1}, {-1, -1},
	}
	return jumpMoves(board, r, c, piece, dirs)
}

func jumpMoves(board [8][8]int, r, c, piece int, dirs [][2]int) []string {
	moves := []string{}
	to := func(r, c int) string { return fmt.Sprintf("%c%d", 'a'+c, 8-r) }
	from := to(r, c)
	for _, d := range dirs {
		nr, nc := r+d[0], c+d[1]
		if !inBounds(nr, nc) {
			continue
		}
		if board[nr][nc] == Empty || isEnemy(piece, board[nr][nc]) {
			moves = append(moves, from+to(nr, nc))
		}
	}
	return moves
}

func slidingMoves(board [8][8]int, r, c, piece int, dirs [][2]int) []string {
	moves := []string{}
	to := func(r, c int) string { return fmt.Sprintf("%c%d", 'a'+c, 8-r) }
	from := to(r, c)
	for _, d := range dirs {
		nr, nc := r+d[0], c+d[1]
		for inBounds(nr, nc) {
			if board[nr][nc] == Empty {
				moves = append(moves, from+to(nr, nc))
			} else {
				if isEnemy(piece, board[nr][nc]) {
					moves = append(moves, from+to(nr, nc))
				}
				break
			}
			nr += d[0]
			nc += d[1]
		}
	}
	return moves
}

func inBounds(r, c int) bool {
	return r >= 0 && r < 8 && c >= 0 && c < 8
}

func isEnemy(p1, p2 int) bool {
	isWhite1 := p1 >= WhitePawn && p1 <= WhiteKing
	isWhite2 := p2 >= WhitePawn && p2 <= WhiteKing
	return isWhite1 != isWhite2
}
