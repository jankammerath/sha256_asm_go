# SHA256 Performance-Test: Go vs. ASM

This repository contains two applications, `sha256_go` is written in Go and `sha256_asm` is written in ASM. Both exist to be benchmarked against each other to outline the performance advantages of ASM over Go. The test scripts are used in combination with the `test.txt` file to have both applications calculate a large number of `sha256` hash values for the text contained within the `test.txt` file.

## Test results

The following test results were recorded on a MacBook M1 Pro (16 GB).

```
# GO

real	4m43.845s
user	2m2.123s
sys	2m0.324s

# ASM

real	3m21.447s
user	1m5.904s
sys	1m30.138s
```

## Special thanks

Special thanks to (Luke Chadwick)[https://github.com/vertis] for assisting with Claude and thus the creation of the ASM version of this application.