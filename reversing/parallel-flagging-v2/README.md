# Parallel Flagging ɘϱnɘvɘЯ [_snakeCTF 2025 Finals_]

**Category**: reversing

## Description

Sometimes they return, this time with no side channels (maybe)


## Solution

The flag in split in 16-bytes blocks, each block goes through an AES round (excluding key add) and a cbc like chain xor is done between the blocks
The order of the chain is random (is done via race conditions) but can be easily bruteforced 
