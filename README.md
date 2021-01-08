## K55 - Linux x86_64 Process Injection Utility (C++11)

## About K55 
The K55 payload injection tool is used for injecting x86_64 shellcode payloads into running processes. The utility was developed using modern C++11 techniques as well as some traditional C linux functions like ``ptrace()``. <br/>

## Installation
1. ``git clone https://github.com/josh0xA/K55.git``<br/>
2. ``cd K55``<br/>
3. ``chmod +x build-install.sh``<br/>
4. ``./build-install.sh``<br/>
### Tests
5. In one terminal (K55/ Directory), run: ``./k55_example_process/k55_test_process``<br/>
7. In another terminal, run the injector: ``./K55``<br/>
