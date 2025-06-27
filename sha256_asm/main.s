; sha256_full.s
; ARM64 macOS assembly implementation of the SHA256 algorithm.
; This program accepts a string as a command-line argument,
; pads it according to SHA256 standard, and computes its hash.
;
; It implements the full SHA256 algorithm directly in assembly,
; including message padding and multi-block compression.
; It does NOT use CommonCrypto.
;
; To compile: clang -o sha256_hasher main.s
; To run:     ./sha256_hasher "your string here"
;
; Example: ./sha256_hasher "Hello World"
; Expected Output: a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e

.global _main           ; Declare _main as a global symbol (entry point)
.align 2                ; Align data/code to a 4-byte boundary

.data                   ; Data section for constants and messages
    ; SHA256 Initial Hash Values (H0 to H7) - 32-bit words
    .balign 4
    IV_H0: .word 0x6a09e667
    IV_H1: .word 0xbb67ae85
    IV_H2: .word 0x3c6ef372
    IV_H3: .word 0xa54ff53a
    IV_H4: .word 0x510e527f
    IV_H5: .word 0x9b05688c
    IV_H6: .word 0x1f83d9ab
    IV_H7: .word 0x5be0cd19

    ; SHA256 Round Constants (K_t) - First 64 constants, 32-bit words
    .balign 4
    K_CONSTANTS:
    .word 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
    .word 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
    .word 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
    .word 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
    .word 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
    .word 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
    .word 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
    .word 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

    ; Format strings for output
    usage_str: .asciz "Usage: %s <string>\n"
    hash_fmt_str: .asciz "%02x"
    newline_str: .asciz "\n"

.text                   ; Code section

; --------------------------------------------------------------------------
; SHA256 Helper Macros
; --------------------------------------------------------------------------

; ROTR (Rotate Right) for 32-bit values.
; dest: destination register (w register)
; val:  source value register (w register)
; n_bits: number of bits to rotate (immediate)
.macro ROTR_32 dest, val, n_bits
    ror \dest, \val, \n_bits
.endmacro

; SHR (Shift Right) for 32-bit values.
; dest: destination register (w register)
; val:  source value register (w register)
; n_bits: number of bits to shift (immediate)
.macro SHR_32 dest, val, n_bits
    lsr \dest, \val, \n_bits
.endmacro

; --------------------------------------------------------------------------
; _sha256_compress_block function
; Computes the SHA256 compression function for a single 64-byte block.
;
; Arguments:
;   x0: Pointer to the 64-byte message block (M)
;   x1: Pointer to the 8 32-bit current hash values (H0-H7) (will be updated)
;   x2: Pointer to the 64 32-bit K_t constants
;
; Returns:
;   Updates the 8 32-bit hash values at the address pointed to by x1.
;
; Working registers (32-bit 'w' variants where applicable):
;   w19-w26:  Working variables a-h (A in w19, B in w20, ..., H in w26)
;   w27-w28:  Temporary registers for SHA256 functions (Ch, Maj, Sigma0, etc.)
;   w3, w4:   Temporary registers for T1/T2 calculation
;   w5:       Temporary for message schedule and loop counter t
;   x10:      Pointer to W[0] on stack
;   x29, x30: Frame pointer, Link Register
;   w0:       Used here as a temporary for T1 calculation, carefully managed.
;   w6, w7:   Used as additional temporary registers for internal calculations
;             within Ch and Maj functions.
; --------------------------------------------------------------------------
_sha256_compress_block:
    ; --- Prologue ---
    ; Save FP, LR
    stp x29, x30, [sp, #-16]!
    mov x29, sp

    ; Save callee-saved registers that this function uses
    ; (x19-x28 are callee-saved, so we must save them if we modify them)
    stp x19, x20, [sp, #-16]!
    stp x21, x22, [sp, #-16]!
    stp x23, x24, [sp, #-16]!
    stp x25, x26, [sp, #-16]!
    ; x27, x28 are used as temporaries, also callee-saved
    stp x27, x28, [sp, #-16]!

    ; Arguments:
    ; x0: message_block_ptr (M)
    ; x1: current_hash_values_ptr (H)
    ; x2: k_constants_ptr (K)

    ; Load current hash values (H0-H7) into working variables (w19-w26 for a-h)
    ldr w19, [x1, #0]   ; w19 = a = H0
    ldr w20, [x1, #4]   ; w20 = b = H1
    ldr w21, [x1, #8]   ; w21 = c = H2
    ldr w22, [x1, #12]  ; w22 = d = H3
    ldr w23, [x1, #16]  ; w23 = e = H4
    ldr w24, [x1, #20]  ; w24 = f = H5
    ldr w25, [x1, #24]  ; w25 = g = H6
    ldr w26, [x1, #28]  ; w26 = h = H7

    ; Store these loaded H values for final addition
    ; Use stack space to save H0-H7, so we can add them back at the end
    sub sp, sp, #32             ; Allocate 32 bytes for current H values (8 words)
    str w19, [sp, #0]           ; Save original a
    str w20, [sp, #4]           ; Save original b
    str w21, [sp, #8]           ; Save original c
    str w22, [sp, #12]          ; Save original d
    str w23, [sp, #16]          ; Save original e
    str w24, [sp, #20]          ; Save original f
    str w25, [sp, #24]          ; Save original g
    str w26, [sp, #28]          ; Save original h

    ; --------------------------------------------------------------------------
    ; Message Schedule W[0..63] preparation
    ; Allocate stack space for W[0..63] (64 words * 4 bytes/word = 256 bytes)
    sub sp, sp, #256
    mov x10, sp             ; x10 points to W[0] on stack

    ; Load W[0..15] from MESSAGE_BLOCK, handling big-endian conversion (rev)
    mov w5, #0              ; Loop counter for W[0..15] (t in w5)
.L_load_W0_15:
    cmp w5, #16
    bge .L_expand_W16_63

    ldr w3, [x0, w5, uxtw #2] ; Load word from M (byte offset by w5*4)
    rev w3, w3                ; Convert from little-endian byte order to big-endian word
    str w3, [x10, w5, uxtw #2] ; Store to W[t] on stack

    add w5, w5, #1            ; t++
    b .L_load_W0_15

.L_expand_W16_63:
    ; Calculate W[16..63]
    ; W[t] = sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16]
    ; t from 16 to 63
    mov w5, #16             ; Loop counter for W[16..63] (t in w5)
.L_calc_W16_63_loop:
    cmp w5, #64
    bge .L_message_schedule_done

    ; Get W[t-16]
    sub w3, w5, #16             ; w3 = t-16
    ldr w27, [x10, w3, uxtw #2] ; w27 = W[t-16]

    ; Get W[t-15] and apply sigma0
    sub w3, w5, #15             ; w3 = t-15
    ldr w28, [x10, w3, uxtw #2] ; w28 = W[t-15]
    ; sigma0(w28) = ROTR(w28, 7) XOR ROTR(w28, 18) XOR SHR(w28, 3)
    ROTR_32 w3, w28, #7
    ROTR_32 w4, w28, #18
    eor w3, w3, w4
    SHR_32 w4, w28, #3
    eor w28, w3, w4             ; w28 now holds sigma0(W[t-15])

    ; Get W[t-7]
    sub w3, w5, #7              ; w3 = t-7
    ldr w3, [x10, w3, uxtw #2]  ; w3 = W[t-7]

    ; Get W[t-2] and apply sigma1
    sub w4, w5, #2              ; w4 = t-2
    ldr w4, [x10, w4, uxtw #2]  ; w4 = W[t-2]
    ; sigma1(w4) = ROTR(w4, 17) XOR ROTR(w4, 19) XOR SHR(w4, 10)
    ROTR_32 w27, w4, #17
    ROTR_32 w28, w4, #19
    eor w27, w27, w28
    SHR_32 w28, w4, #10
    eor w4, w27, w28            ; w4 now holds sigma1(W[t-2])

    ; W[t] = sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16]
    add w27, w27, w3            ; w27 = W[t-16] + W[t-7]
    add w27, w27, w28           ; w27 = w27 + sigma0(W[t-15])
    add w27, w27, w4            ; w27 = w27 + sigma1(W[t-2])

    str w27, [x10, w5, uxtw #2] ; Store W[t] on stack

    add w5, w5, #1            ; t++
    b .L_calc_W16_63_loop

.L_message_schedule_done:

    ; --------------------------------------------------------------------------
    ; SHA256 Compression Function (64 Rounds)
    ;
    ; Initial A-H values are in w19-w26
    ; Current message word W[t] is loaded as needed from stack (x10 points to W[0])
    ; Current K[t] constant is loaded as needed from K_CONSTANTS (x2 points to K[0])

    mov w5, #0              ; Loop counter for rounds (t = 0 to 63)
.L_sha256_rounds_loop:
    cmp w5, #64
    bge .L_sha256_rounds_end

    ; Load K[t]
    ldr w3, [x2, w5, uxtw #2] ; w3 = K[t]

    ; Load W[t]
    ldr w4, [x10, w5, uxtw #2] ; w4 = W[t]

    ; Calculate T1 = H + Sigma1(E) + Ch(E,F,G) + K[t] + W[t]
    ; H is w26
    ; E is w23
    ; F is w24
    ; G is w25

    ; Sigma1(E)
    ; Input E (w23). Output w27 = Sigma1(E)
    ROTR_32 w28, w23, #6
    ROTR_32 w30, w23, #11 ; Use w30 as temporary for rotation
    eor w28, w28, w30
    ROTR_32 w30, w23, #25 ; Reuse w30
    eor w27, w28, w30 ; w27 = Sigma1(E)

    ; Ch(E,F,G)
    ; Input E (w23), F (w24), G (w25). Output w28 = Ch(E,F,G)
    and w30, w23, w24        ; E AND F (using w30 as temp)
    mvn w6, w23             ; NOT E (using w6 as temp, avoiding w0 clobber)
    and w6, w6, w25         ; (NOT E) AND G
    eor w28, w30, w6        ; w28 = Ch(E,F,G)

    ; T1 = H + Sigma1(E) + Ch(E,F,G) + K[t] + W[t]
    add w0, w26, w27        ; H + Sigma1(E) (w0 is used for T1, and will be preserved)
    add w0, w0, w28         ; H + Sigma1(E) + Ch(E,F,G)
    add w0, w0, w3          ; T1 = ... + K[t] (w3 is K[t])
    add w0, w0, w4          ; T1 = ... + W[t] (w4 is W[t]) ; w0 is now T1

    ; Calculate T2 = Sigma0(A) + Maj(A,B,C)
    ; A is w19
    ; B is w20
    ; C is w21

    ; Sigma0(A)
    ; Input A (w19). Output w27 = Sigma0(A)
    ROTR_32 w28, w19, #2
    ROTR_32 w30, w19, #13
    eor w28, w28, w30
    ROTR_32 w30, w19, #22
    eor w27, w28, w30 ; w27 = Sigma0(A)

    ; Maj(A,B,C)
    ; Input A (w19), B (w20), C (w21). Output w28 = Maj(A,B,C)
    and w6, w19, w20        ; w6 = A AND B (using w6 as temp)
    and w7, w19, w21        ; w7 = A AND C (using w7 as temp)
    eor w6, w6, w7          ; w6 = (A AND B) XOR (A AND C)
    and w7, w20, w21        ; w7 = B AND C (using w7 as temp)
    eor w28, w6, w7         ; w28 = Maj(A,B,C)

    ; T2 = Sigma0(A) + Maj(A,B,C)
    add w30, w27, w28         ; w30 = T2

    ; Update working variables (a-h)
    ; H = G
    mov w26, w25
    ; G = F
    mov w25, w24
    ; F = E
    mov w24, w23
    ; E = D + T1
    add w23, w22, w0        ; w23 = w22 (D) + w0 (T1)
    ; D = C
    mov w22, w21
    ; C = B
    mov w21, w20
    ; B = A
    mov w20, w19
    ; A = T1 + T2
    add w19, w0, w30        ; w19 = w0 (T1) + w30 (T2)

    add w5, w5, #1        ; Increment round counter
    b .L_sha256_rounds_loop

.L_sha256_rounds_end:

    ; Add working variables (a-h) back to initial hash values (from stack)
    ; Restore original H values from stack (where they were saved)
    ldr w3, [sp, #0]   ; w3 = H0_original
    ldr w4, [sp, #4]   ; w4 = H1_original
    ldr w5, [sp, #8]   ; w5 = H2_original
    ldr w6, [sp, #12]  ; w6 = H3_original
    ldr w7, [sp, #16]  ; w7 = H4_original
    ldr w8, [sp, #20]  ; w8 = H5_original
    ldr w9, [sp, #24]  ; w9 = H6_original
    ldr w10, [sp, #28] ; w10 = H7_original

    add w19, w19, w3    ; a = a + H0_original
    add w20, w20, w4    ; b = b + H1_original
    add w21, w21, w5    ; c = c + H2_original
    add w22, w22, w6    ; d = d + H3_original
    add w23, w23, w7    ; e = e + H4_original
    add w24, w24, w8    ; f = f + H5_original
    add w25, w25, w9    ; g = g + H6_original
    add w26, w26, w10   ; h = h + H7_original

    ; Store final hash values back to the address provided by x1
    str w19, [x1, #0]
    str w20, [x1, #4]
    str w21, [x1, #8]
    str w22, [x1, #12]
    str w23, [x1, #16]
    str w24, [x1, #20]
    str w25, [x1, #24]
    str w26, [x1, #28]

    ; --- Epilogue ---
    ; Deallocate stack space used for W array and saved H values
    add sp, sp, #256    ; Deallocate W array (for W[0..63])
    add sp, sp, #32     ; Deallocate saved H values

    ; Restore saved registers
    ldp x27, x28, [sp], #16
    ldp x25, x26, [sp], #16
    ldp x23, x24, [sp], #16
    ldp x21, x22, [sp], #16
    ldp x19, x20, [sp], #16

    ; Restore FP, LR
    ldp x29, x30, [sp], #16
    ret                     ; Return from _sha256_compress_block

; --------------------------------------------------------------------------
; _main function
; Entry point for the program. Handles argument parsing, padding,
; multi-block processing, and final output.
; --------------------------------------------------------------------------
_main:
    ; --- Prologue ---
    stp x29, x30, [sp, #-16]! ; Save FP, LR
    mov x29, sp               ; Set FP

    ; Save callee-saved registers that _main uses (e.g., x19, x20, x21 for program arguments/state)
    stp x19, x20, [sp, #-16]! ; x19: input_str_ptr, x20: input_len_bytes
    stp x21, x22, [sp, #-16]! ; x21: padded_len_bytes, x22: num_blocks

    ; --- Argument Count Check ---
    ; Check if argc (in x0) is less than 2. We need at least 2 arguments:
    ; the program name (argv[0]) and the input string (argv[1]).
    cmp x0, #2
    blt .L_usage_error        ; If x0 < 2, branch to the error handling label

    ; --- Get Input String Pointer (argv[1]) ---
    ldr x19, [x1, #8]         ; x19 = input_str_ptr = argv[1]

    ; --- Call strlen to get the input string length ---
    mov x0, x19               ; Move input_str_ptr to x0 for strlen
    bl _strlen                ; Call _strlen, result in x0
    mov x20, x0               ; x20 = input_len_bytes = strlen(input_str_ptr)

    ; --- SHA256 Padding Calculation ---
    ; Original message length in bits = input_len_bytes * 8
    ; x23 will store the message length in bits (L_bits)
    mov x23, x20              ; Copy input_len_bytes to x23
    lsl x23, x23, #3          ; x23 = input_len_bytes * 8 (L_bits)

    ; Calculate k (number of zero bits to append)
    ; k = (448 - (L_bits + 1) % 512) % 512
    ; (L_bits + 1) % 512
    add x24, x23, #1          ; x24 = L_bits + 1
    ; Load 512 into a temporary register for udiv/mul
    mov x27, #512             ; Use x27 as temp for 512
    udiv x25, x24, x27        ; x25 = (L_bits + 1) / 512 (quotient)
    mul x25, x25, x27         ; x25 = (quotient) * 512
    sub x24, x24, x25         ; x24 = (L_bits + 1) % 512 (remainder)

    ; k = (448 - remainder) % 512
    mov x25, #448
    sub x25, x25, x24         ; x25 = 448 - remainder
    ; Load 512 into a temporary register for udiv/mul
    ; x27 still holds 512
    udiv x24, x25, x27        ; x24 = (448 - remainder) / 512 (quotient)
    mul x24, x24, x27         ; x24 = (quotient) * 512
    sub x25, x25, x24         ; x25 = k = (448 - remainder) % 512 (number of zero bits)

    ; Padded length in bits = L_bits + 1 + k + 64
    add x21, x23, #1          ; x21 = L_bits + 1
    add x21, x21, x25         ; x21 = L_bits + 1 + k
    add x21, x21, #64         ; x21 = padded_len_bits

    ; Padded length in bytes = padded_len_bits / 8
    lsr x21, x21, #3          ; x21 = padded_len_bytes

    ; Number of 64-byte blocks = padded_len_bytes / 64
    lsr x22, x21, #6          ; x22 = num_blocks

    ; --- Allocate Stack Space for Padded Message ---
    ; Need to allocate padded_len_bytes on stack. Round up to nearest 16 for alignment.
    add x27, x21, #15         ; Add 15 for rounding up
    and x27, x27, #-16        ; Align to 16 bytes
    sub sp, sp, x27           ; Allocate padded message buffer
    mov x28, sp               ; x28 points to the padded message buffer

    ; --- Copy original string to padded buffer ---
    mov x3, #0                ; Loop counter (byte index)
.L_copy_string_loop:
    cmp x3, x20               ; Compare byte index with input_len_bytes
    bge .L_copy_string_done

    ldrb w4, [x19, x3]        ; Load byte from input string
    strb w4, [x28, x3]        ; Store byte to padded buffer
    add x3, x3, #1
    b .L_copy_string_loop

.L_copy_string_done:
    ; --- Append '1' bit (0x80 byte) ---
    ; x3 is currently the index of the byte *after* the original string.
    ; This is where the '1' bit (0x80) should go.
    mov w4, #0x80
    strb w4, [x28, x3]        ; Store 0x80 at the end of the original message
    add x3, x3, #1            ; Move past the 0x80 byte

    ; --- Append '0' bits ---
    ; 'x3' is now at (input_len_bytes + 1)
    ; We need to fill up to (padded_len_bytes - 8) with zeros.
    mov w4, #0                ; w4 = 0 for storing zero bytes
.L_append_zeros_loop:
    sub x27, x21, #8          ; Calculate (padded_len_bytes - 8) (Re-use x27 here, it holds aligned padded_len_bytes)
    cmp x3, x27               ; Compare current offset with (padded_len_bytes - 8)
    bge .L_append_zeros_done

    strb w4, [x28, x3]        ; Store a zero byte (from w4 which is 0)
    add x3, x3, #1
    b .L_append_zeros_loop

.L_append_zeros_done:
    ; --- Append 64-bit message length (in bits, big-endian) ---
    ; L_bits is in x23 (64-bit register)
    ; Store at (padded_len_bytes - 8)
    ; Address: x28 (base) + (x21 - 8) (offset)
    sub x3, x21, #8             ; x3 = offset for length (padded_len_bytes - 8)
    rev x23, x23                ; Convert 64-bit length to big-endian byte order
    str x23, [x28, x3]          ; Store L_bits (64-bit value) directly

    ; --- Initialize Hash Values (H0-H7) for the entire message ---
    ; Allocate 32 bytes on stack for final hash result, initialized with IVs
    sub sp, sp, #32
    mov x4, sp              ; x4 points to the current hash accumulator (H_final)

    adrp x0, IV_H0@PAGE
    add x0, x0, IV_H0@PAGEOFF ; x0 = address of IV_H0
    mov w5, #0                ; Loop counter for copying IVs
.L_copy_IVs_main:
    cmp w5, #8
    bge .L_IVs_copied_main
    ldr w3, [x0, w5, uxtw #2] ; Load IV word
    str w3, [x4, w5, uxtw #2] ; Store to H_final buffer on stack
    add w5, w5, #1
    b .L_copy_IVs_main

.L_IVs_copied_main:

    ; --- Process Each 64-byte Block ---
    mov x3, #0                  ; Block counter (i)
.L_process_blocks_loop:
    cmp x3, x22                 ; Compare block counter with num_blocks
    bge .L_all_blocks_processed

    ; Calculate pointer to current block
    ; block_ptr = padded_message_buffer + (block_counter * 64)
    mov x0, x28                 ; base address of padded message
    add x0, x0, x3, lsl #6      ; x0 = block_ptr (block_counter * 64)

    ; Call _sha256_compress_block
    ; x0: pointer to current message block
    ; x1: pointer to current hash values (x4, H_final)
    ; x2: pointer to K_CONSTANTS
    mov x1, x4                  ; Pass the address of H_final
    adrp x2, K_CONSTANTS@PAGE
    add x2, x2, K_CONSTANTS@PAGEOFF

    bl _sha256_compress_block   ; Perform compression for this block

    add x3, x3, #1              ; Increment block counter
    b .L_process_blocks_loop

.L_all_blocks_processed:

    ; --- Print the SHA256 Hash ---
    ; The final hash is in the buffer pointed to by x4
    mov x3, #0                  ; Initialize loop counter 'i' to 0 (x3 = i)
    mov x5, #32                 ; Set loop limit to 32 (x5 = max_bytes)

.L_print_loop:
    cmp x3, x5                  ; Compare loop counter (x3) with max_bytes (x5)
    bge .L_print_loop_end       ; If x3 >= x5, loop has finished, branch to end

    ; Load current byte from digest buffer (x4 holds address)
    ldrb w6, [x4, x3]           ; Load byte at (digest_buffer_address + i) into w6.

    ; Call printf("%02x", byte)
    adrp x0, hash_fmt_str@PAGE
    add x0, x0, hash_fmt_str@PAGEOFF
    mov x1, w6                  ; Move the byte to print (from w6) to x1.
    bl _printf                  ; Branch and Link to the _printf function.

    add x3, x3, #1              ; Increment loop counter (i++)
    b .L_print_loop             ; Branch back to the beginning of the loop

.L_print_loop_end:
    ; --- Print a Newline Character ---
    adrp x0, newline_str@PAGE
    add x0, x0, newline_str@PAGEOFF
    bl _printf

    ; --- Success Exit ---
    mov x0, #0                  ; Set return value to 0 (indicating success)
    b .L_exit                   ; Branch to the common exit routine

.L_usage_error:
    ; --- Error Handling: Print Usage Message ---
    adrp x0, usage_str@PAGE     ; Load address of usage_str into x0.
    add x0, x0, usage_str@PAGEOFF
    ; Need argv[0] for the %s in the usage string.
    ldr x1, [x1]                ; Load the pointer to argv[0] into x1.
    bl _printf                  ; Call printf to print the usage message.

    ; --- Error Exit ---
    mov x0, #1                  ; Set return value to 1 (indicating error)

.L_exit:
    ; --- Epilogue ---
    ; Deallocate all stack space allocated in _main
    ; (from bottom to top: H_final (32), padded_message_buffer (x27 bytes))
    add sp, sp, #32             ; Deallocate H_final
    add sp, sp, x27             ; Deallocate padded_message_buffer (use stored aligned size)

    ; Restore saved registers
    ldp x21, x22, [sp], #16
    ldp x19, x20, [sp], #16

    ; Restore FP, LR
    ldp x29, x30, [sp], #16
    ret                         ; Return from _main
