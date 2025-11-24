# Shellcode Wannabe [*snakeCTF 2025 Finals*]

**Category**: pwn

## Description

I made a platform where you can input shellcode bytes and review your shellcode before executing it. But will your shellcode actually run? In fact, I don't even know why I put the execute choice there...

## Solution

Upon analysis of the decompiled binary, it is observed that at the start of the challenge, an executable memory area is mapped into a variable named `shellcode`. Access to this executable region is not provided through the program's standard functionality; therefore, gaining control of this memory is established as the objective.

```c
    void initialize_challenge(void) {
        int iVar1;
        time_t tVar2;
        int local_c;
        
        setbuf(stdout,(char *)0x0);
        setbuf(stdin,(char *)0x0);
        setbuf(stderr,(char *)0x0);
        tVar2 = time((time_t *)0x0);
        srand((uint)tVar2);
        menu();
        for (local_c = 0; local_c < 0x10; local_c = local_c + 1) {
            iVar1 = rand();
            *(char *)((long)&secret + (long)local_c) = (char)iVar1 + (char)(iVar1 / 0x1a) * -0x1a + 'A';
        }
        shellcode = mmap((void *)0x0,0x400,7,0x22,-1,0);
        if (shellcode == (void *)0xffffffffffffffff) {
            perror("mmap");
                            /* WARNING: Subroutine does not return */
            exit(1);
        }
        return;
    }
```

During the printing process, the binary checks for a 16-byte `secret` located at the end of the user-supplied `code` buffer (at offset `0x3e0`). This buffer is populated via the 'edit' option. If this check succeeds, the final `32` bytes of the `code` array are copied into the output buffer using `memcpy()`. This suggests that if the `code` buffer is correctly filled with `(1024 - 32)` or `992` bytes of valid instructions, followed by the original secret, the secret itself will be leaked in the subsequent output. To ensure the disassembly process succeeds, a *NOP sled* (using the `0x90` opcode) should be used for these 992 bytes.

A format string vulnerability is identified in the `print_assembly` function. As shown in the code below, the `snprintf` call uses the contents of the output buffer (which contains the user-supplied data) as its format string parameter. This allows for the resolution of format specifiers like `%s` or `%p`. To exploit this vulnerability, the secret must first be leaked as described. The `code` buffer can then be populated with the 992-byte NOP sled, followed by the 16-byte secret. The remaining 16 bytes (completing the 32-byte chunk copied by `memcpy`) can be filled with format string specifiers to read data from the stack.

```c
char * print_assembly(long param_1,int param_2) {
        // ... previous code
        iVar1 = strncmp((char *)(param_1 + 0x3e0),(char *)&secret,0x10);
        if (iVar1 != 0) {
            pcVar2 = (char *)0x0;
            goto LAB_001012e7;
        }

        // ... other code ...

        if (iStack_10064 == 0x3e0) {
            memcpy(acStack_10018 + lStack_10038,(void *)(param_1 + 0x3e0),0x20);
        }
        snprintf(pcStack_10028,0x10000,acStack_10018);
        // following code ...
    }
```

Although this vulnerability could provide an *arbitrary write*, this path is not useful as **Full RELRO** is enabled on the binary. Instead, an *arbitrary read* can be utilised. By carefully crafting the format string, the stack can be read to find the buffer's own address and the return address to the `main` function. Leaking this return address allows for the base address of the binary to be calculated. From the binary's base address, the address of the global `shellcode` pointer (which points to the RWX memory region) can be determined.

A payload can then be constructed to leak the pointer. This payload consists of the 992-byte NOP sled, the 16-byte secret, a format specifier (e.g., `%(n+1)$s`), and the previously calculated address of the `shellcode` global variable. Here, `n` represents the stack offset from the format string itself to the `shellcode_address` part of the payload. This causes `snprintf` to interpret the *value* of the `shellcode` variable (i.e., the address of the mmaped region) as a string, leaking it. Since the mmaped address itself could contain NULL bytes, which would terminate the `%s` read, this process may need to be iterated (e.g., byte-by-byte) to ensure the full 8-byte pointer is recovered.

Once this task is completed, the address of the executable mmaped memory is known. The next step is to induce the program to use this address for shellcode execution.

An inspection of the `main` function reveals that the `code` variable is allocated with `malloc(0x400)`. When the 'delete' option is chosen, this variable is passed to `free()`, but the `code` pointer is **not set to NULL** afterwards. This creates a **Use-After-Free (UAF)** vulnerability. Because the pointer remains valid, the 'edit' option can be used to write to the freed chunk, and the 'delete' option can be called again, resulting in a **Double Free**. Given that the challenge uses glibc 2.27, these vulnerabilities can be used to perform a tcache poisoning attack, as metadata protections (like safe-linking) are not present.

```c
    // ... previous code
    iVar1 = strncmp(local_28,"create",6);
    if (iVar1 != 0) break;
    local_38 = (code *)malloc(0x400);
    uVar2 = DAT_00302058;
    *(undefined8 *)(local_38 + 0x3e0) = secret;
    *(undefined8 *)(local_38 + 1000) = uVar2;

    // ... other code ...

    iVar1 = strncmp(local_28,"delete",6);
    if (iVar1 != 0) break;
    free(local_38);

    // following code ...
```

Proceeding with the solution, the `code` variable is freed. An immediate second call to 'delete' (free) on the same pointer is performed. This places the chunk in the tcache list twice (a **double free**). The 'edit' option is then used; this UAF overwrites the `fd` (forward) pointer of the tcache chunk with the address of the executable mmaped `shellcode` region, which was leaked earlier. Finally, `malloc` is called twice: the first call returns the original chunk, and the **second call returns a pointer to the `shellcode` mmaped region**. The `code` variable in `main` now points to executable memory. The 'edit' option can be used a final time to write a shellcode payload into this region, which is then executed using the 'execute' option.

[solve.py](./attachments/solve.py)