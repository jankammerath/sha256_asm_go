.section __TEXT,__text,regular,pure_instructions
.global _main
.align 4

// External function declarations
.extern _malloc
.extern _free
.extern _printf
.extern _putchar

// SHA-256 constants (first 32 bits of the fractional parts of the cube roots of the first 64 primes)
.section __DATA,__data
.align 4
k_constants:
    .word 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
    .word 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
    .word 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
    .word 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
    .word 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
    .word 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
    .word 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
    .word 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
    .word 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
    .word 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
    .word 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
    .word 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
    .word 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
    .word 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
    .word 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
    .word 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

// Initial hash values (first 32 bits of the fractional parts of the square roots of the first 8 primes)
initial_hash:
    .word 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
    .word 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19

// Hex characters for output
hex_chars:
    .ascii "0123456789abcdef"

// Messages
usage_msg:
    .ascii "Usage: ./sha256_asm <string>\n\0"
empty_msg:
    .ascii "Please provide a string to hash.\n\0"
newline:
    .ascii "\n\0"

.section __TEXT,__text

// Macros for SHA-256 operations
.macro ROTR reg, src, count
    ror \reg, \src, #\count
.endm

.macro SHR reg, src, count
    lsr \reg, \src, #\count
.endm

// Main function
_main:
    // Save registers
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    stp x19, x20, [sp, #-16]!
    stp x21, x22, [sp, #-16]!
    stp x23, x24, [sp, #-16]!
    stp x25, x26, [sp, #-16]!
    stp x27, x28, [sp, #-16]!

    // Check argument count
    cmp x0, #2
    blt usage_error

    // Get the string argument
    ldr x19, [x1, #8]  // argv[1]
    
    // Check if string is empty
    ldrb w0, [x19]
    cbz w0, empty_error

    // Calculate string length
    mov x20, x19
    mov x21, #0
strlen_loop:
    ldrb w0, [x20, x21]
    cbz w0, strlen_done
    add x21, x21, #1
    b strlen_loop
strlen_done:
    // x21 now contains the string length

    // Prepare message for SHA-256 (padding)
    // We need: original message + 1 bit + zeros + 64-bit length
    // Round up to next 512-bit (64-byte) boundary
    
    // Calculate padded length
    add x22, x21, #1      // +1 for the '1' bit (0x80 byte)
    add x22, x22, #8      // +8 for 64-bit length
    add x22, x22, #63     // Round up to 64-byte boundary
    and x22, x22, #-64    // Clear lower 6 bits
    
    // Allocate memory for padded message
    mov x0, x22
    bl _malloc
    mov x23, x0           // x23 = padded message buffer
    
    // Copy original message
    mov x24, #0
copy_loop:
    cmp x24, x21
    beq copy_done
    ldrb w0, [x19, x24]
    strb w0, [x23, x24]
    add x24, x24, #1
    b copy_loop
copy_done:
    
    // Add padding bit (0x80)
    mov w0, #0x80
    strb w0, [x23, x21]
    add x24, x21, #1
    
    // Zero remaining bytes except last 8
    sub x25, x22, #8
zero_loop:
    cmp x24, x25
    beq zero_done
    strb wzr, [x23, x24]
    add x24, x24, #1
    b zero_loop
zero_done:
    
    // Store length in bits (big-endian) in last 8 bytes
    lsl x21, x21, #3      // Convert to bits
    // Store as big-endian 64-bit (high 32 bits first, then low 32 bits)
    mov w26, #0           // High 32 bits (always 0 for reasonable string lengths)
    rev w27, w21          // Low 32 bits in big-endian
    str w26, [x23, x25]   // Store high 32 bits
    add x28, x25, #4
    str w27, [x23, x28]   // Store low 32 bits
    
    // Initialize hash values
    adrp x24, initial_hash@PAGE
    add x24, x24, initial_hash@PAGEOFF
    sub sp, sp, #32       // Space for hash values (8 words)
    
    // Copy initial hash values
    mov x25, #0
init_hash_loop:
    cmp x25, #8
    beq init_hash_done
    ldr w0, [x24, x25, lsl #2]
    str w0, [sp, x25, lsl #2]
    add x25, x25, #1
    b init_hash_loop
init_hash_done:
    
    // Process message in 512-bit chunks
    mov x24, #0           // Chunk offset
process_chunks:
    cmp x24, x22
    beq chunks_done
    
    // Process one 512-bit chunk
    add x25, x23, x24     // Current chunk address
    mov x0, x25
    mov x1, sp            // Hash values
    bl process_chunk
    
    add x24, x24, #64
    b process_chunks
chunks_done:
    
    // Print hash as hex
    mov x24, #0
print_hash:
    cmp x24, #8
    beq print_done
    
    ldr w25, [sp, x24, lsl #2]
    rev w25, w25          // Convert to big-endian for output
    
    // Print each byte as hex (8 hex digits per 32-bit word)
    mov x26, #8
print_word:
    cbz x26, next_word
    
    lsr w27, w25, #28
    and w27, w27, #0xf
    adrp x28, hex_chars@PAGE
    add x28, x28, hex_chars@PAGEOFF
    ldrb w0, [x28, x27]
    bl _putchar
    
    lsl w25, w25, #4
    sub x26, x26, #1
    b print_word
    
next_word:
    add x24, x24, #1
    b print_hash
    
print_done:
    // Print newline
    mov w0, #'\n'
    bl _putchar
    
    // Free allocated memory
    mov x0, x23
    bl _free
    
    add sp, sp, #32       // Remove hash values from stack
    mov w0, #0
    b exit

usage_error:
    adrp x0, usage_msg@PAGE
    add x0, x0, usage_msg@PAGEOFF
    bl _printf
    mov w0, #1
    b exit

empty_error:
    adrp x0, empty_msg@PAGE
    add x0, x0, empty_msg@PAGEOFF
    bl _printf
    mov w0, #1
    b exit

exit:
    // Restore registers
    ldp x27, x28, [sp], #16
    ldp x25, x26, [sp], #16
    ldp x23, x24, [sp], #16
    ldp x21, x22, [sp], #16
    ldp x19, x20, [sp], #16
    ldp x29, x30, [sp], #16
    ret

// Process one 512-bit chunk
// x0 = chunk address, x1 = hash values address
process_chunk:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    sub sp, sp, #256      // Space for W array (64 words)
    stp x19, x20, [sp, #-16]!
    stp x21, x22, [sp, #-16]!
    stp x23, x24, [sp, #-16]!
    stp x25, x26, [sp, #-16]!
    stp x27, x28, [sp, #-16]!
    
    mov x19, x0           // Chunk address
    mov x20, x1           // Hash values address
    add x21, sp, #80      // W array address
    
    // Copy chunk to W[0..15] (read bytes and pack into big-endian 32-bit words)
    mov x22, #0
copy_chunk:
    cmp x22, #16
    beq copy_chunk_done
    
    // Read 4 bytes and pack them into a big-endian 32-bit word
    lsl x23, x22, #2      // x23 = byte offset (x22 * 4)
    ldrb w24, [x19, x23]  // Load byte 0
    lsl w24, w24, #24
    add x23, x23, #1
    ldrb w25, [x19, x23]  // Load byte 1
    lsl w25, w25, #16
    orr w24, w24, w25
    add x23, x23, #1
    ldrb w25, [x19, x23]  // Load byte 2
    lsl w25, w25, #8
    orr w24, w24, w25
    add x23, x23, #1
    ldrb w25, [x19, x23]  // Load byte 3
    orr w24, w24, w25
    
    str w24, [x21, x22, lsl #2]
    add x22, x22, #1
    b copy_chunk
copy_chunk_done:
    
    // Extend W[16..63]
    mov x22, #16
extend_w:
    cmp x22, #64
    beq extend_done
    
    // W[i] = σ1(W[i-2]) + W[i-7] + σ0(W[i-15]) + W[i-16]
    sub x23, x22, #2
    ldr w24, [x21, x23, lsl #2]  // W[i-2]
    bl sigma1
    mov w25, w0                   // σ1(W[i-2])
    
    sub x23, x22, #7
    ldr w26, [x21, x23, lsl #2]  // W[i-7]
    
    sub x23, x22, #15
    ldr w24, [x21, x23, lsl #2]  // W[i-15]
    bl sigma0
    mov w27, w0                   // σ0(W[i-15])
    
    sub x23, x22, #16
    ldr w28, [x21, x23, lsl #2]  // W[i-16]
    
    add w24, w25, w26
    add w24, w24, w27
    add w24, w24, w28
    str w24, [x21, x22, lsl #2]
    
    add x22, x22, #1
    b extend_w
extend_done:
    
    // Initialize working variables
    ldp w2, w3, [x20]         // a, b
    ldp w4, w5, [x20, #8]     // c, d
    ldp w6, w7, [x20, #16]    // e, f
    ldp w8, w9, [x20, #24]    // g, h
    
    // Main loop (64 rounds)
    adrp x23, k_constants@PAGE
    add x23, x23, k_constants@PAGEOFF
    mov x22, #0
main_loop:
    cmp x22, #64
    beq main_loop_done
    
    // T1 = h + Σ1(e) + Ch(e,f,g) + K[i] + W[i]
    mov w24, w9               // h
    mov w0, w6                // e
    bl big_sigma1
    add w24, w24, w0          // h + Σ1(e)
    
    // Ch(e,f,g) = (e & f) ^ (~e & g)
    and w25, w6, w7           // e & f
    mvn w26, w6               // ~e
    and w26, w26, w8          // ~e & g
    eor w25, w25, w26         // Ch(e,f,g)
    add w24, w24, w25         // h + Σ1(e) + Ch(e,f,g)
    
    ldr w25, [x23, x22, lsl #2]  // K[i]
    add w24, w24, w25            // + K[i]
    
    ldr w25, [x21, x22, lsl #2]  // W[i]
    add w24, w24, w25            // T1 = h + Σ1(e) + Ch(e,f,g) + K[i] + W[i]
    
    // T2 = Σ0(a) + Maj(a,b,c)
    mov w0, w2                // a
    bl big_sigma0
    mov w25, w0               // Σ0(a)
    
    // Maj(a,b,c) = (a & b) ^ (a & c) ^ (b & c)
    and w26, w2, w3           // a & b
    and w27, w2, w4           // a & c
    and w28, w3, w4           // b & c
    eor w26, w26, w27
    eor w26, w26, w28         // Maj(a,b,c)
    add w25, w25, w26         // T2 = Σ0(a) + Maj(a,b,c)
    
    // Update working variables
    mov w9, w8                // h = g
    mov w8, w7                // g = f
    mov w7, w6                // f = e
    add w6, w5, w24           // e = d + T1
    mov w5, w4                // d = c
    mov w4, w3                // c = b
    mov w3, w2                // b = a
    add w2, w24, w25          // a = T1 + T2
    
    add x22, x22, #1
    b main_loop
main_loop_done:
    
    // Add compressed chunk to hash values
    ldr w24, [x20]
    add w24, w24, w2
    str w24, [x20]
    
    ldr w24, [x20, #4]
    add w24, w24, w3
    str w24, [x20, #4]
    
    ldr w24, [x20, #8]
    add w24, w24, w4
    str w24, [x20, #8]
    
    ldr w24, [x20, #12]
    add w24, w24, w5
    str w24, [x20, #12]
    
    ldr w24, [x20, #16]
    add w24, w24, w6
    str w24, [x20, #16]
    
    ldr w24, [x20, #20]
    add w24, w24, w7
    str w24, [x20, #20]
    
    ldr w24, [x20, #24]
    add w24, w24, w8
    str w24, [x20, #24]
    
    ldr w24, [x20, #28]
    add w24, w24, w9
    str w24, [x20, #28]
    
    // Restore registers and return
    ldp x27, x28, [sp], #16
    ldp x25, x26, [sp], #16
    ldp x23, x24, [sp], #16
    ldp x21, x22, [sp], #16
    ldp x19, x20, [sp], #16
    add sp, sp, #256
    ldp x29, x30, [sp], #16
    ret

// σ0(x) = ROTR(x,7) ⊕ ROTR(x,18) ⊕ SHR(x,3)
sigma0:
    ror w1, w24, #7
    ror w2, w24, #18
    lsr w3, w24, #3
    eor w0, w1, w2
    eor w0, w0, w3
    ret

// σ1(x) = ROTR(x,17) ⊕ ROTR(x,19) ⊕ SHR(x,10)
sigma1:
    ror w1, w24, #17
    ror w2, w24, #19
    lsr w3, w24, #10
    eor w0, w1, w2
    eor w0, w0, w3
    ret

// Σ0(x) = ROTR(x,2) ⊕ ROTR(x,13) ⊕ ROTR(x,22)
big_sigma0:
    ror w1, w0, #2
    ror w2, w0, #13
    ror w3, w0, #22
    eor w0, w1, w2
    eor w0, w0, w3
    ret

// Σ1(x) = ROTR(x,6) ⊕ ROTR(x,11) ⊕ ROTR(x,25)
big_sigma1:
    ror w1, w0, #6
    ror w2, w0, #11
    ror w3, w0, #25
    eor w0, w1, w2
    eor w0, w0, w3
    ret
