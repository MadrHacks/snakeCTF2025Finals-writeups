# GoFish [_snakeCTF 2024 Finals_]

**Category**: reversing

## Description

I've created a brand new chess platform with a unique authentication system!  
By proving your skills by solving a few chess puzzles the system will understand who you are.  
Of course, you’ll still need the password ;)

### Hints

- This is hint given during the CTF for this challenge.
- This is the second hint cause the challenge was impossible to solve.

## Solution

We have to solve 40 chess puzzles and get the best move to get the flag.
The puzzles are randomly generated with a seed between 0 and 10000, the best move is also selected randomly with the same seed so we can bruteforce it.

After all the right answers are given the password is generated using a custom hash and all the moves as input.

solve script [Here](./attachments/solve.go).
