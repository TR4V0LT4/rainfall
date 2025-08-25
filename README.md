# RainFall
![header](/binaries/rain.jpg)
## Overview

RainFall is a binary exploitation wargame that focuses on teaching various memory corruption vulnerabilities and exploitation techniques. This repository contains detailed writeups and solutions for all levels of the RainFall challenge.

## Project Structure

```
rainfall/
├── README.md           # This file
├── binaries/           # contain the binaries of all the levels
├── level0-9/              
    ├── writeup.md      # Detailed solutions for this level
    ├── flag            # The flag of this level 
    ├── source.c         # decompiled binary
```

## Challenge Levels

### Level 1: Stack Buffer Overflow
- **Technique**: Classic stack buffer overflow
- **Objective**: Overwrite return address to execute system("/bin/sh")
- **Key Concepts**: Stack layout, return address control, function arguments

### Level 2: Return-to-Heap Exploitation
- **Technique**: Heap-based shellcode execution
- **Objective**: Bypass stack execution prevention using heap
- **Key Concepts**: NX bit bypass, heap memory layout, shellcode injection

### Level 3: Format String Vulnerability (Basic)
- **Technique**: Format string attack to overwrite global variable
- **Objective**: Change global variable value to trigger shell
- **Key Concepts**: Format string vulnerabilities, %n specifier, memory writes

### Level 4: Format String Vulnerability (Advanced)
- **Technique**: Format string attack with large value
- **Objective**: Write specific large value to global variable
- **Key Concepts**: Large value format string writes, padding calculations

### Level 5: GOT Overwrite via Format String
- **Technique**: Global Offset Table manipulation
- **Objective**: Redirect exit() call to custom function
- **Key Concepts**: GOT/PLT, function pointer hijacking, multi-byte writes

### Level 6: Heap Overflow with Function Pointer
- **Technique**: Heap buffer overflow
- **Objective**: Overwrite function pointer in heap
- **Key Concepts**: Heap layout, malloc/free, function pointer control

### Level 7: Two-Stage Heap Overflow
- **Technique**: Complex heap manipulation
- **Objective**: Multi-stage overflow to control execution flow
- **Key Concepts**: Heap chunk manipulation, pointer arithmetic, staged attacks

## Tools and Requirements

### Required Tools
- **GDB**: GNU Debugger for analysis and exploitation
- **Python**: For payload generation and automation
- **readelf**: For binary analysis and GOT/PLT inspection
- **objdump**: For disassembly and code analysis


## Binary Protections

Most RainFall binaries have minimal protections:
- **RELRO**: Disabled
- **Stack Canaries**: Disabled  
- **NX Bit**: Varies by level
- **PIE**: Disabled
- **ASLR**: Disabled

## Common Exploitation Techniques

### 1. Buffer Overflow
- Stack-based overflows to control return addresses
- Heap-based overflows to corrupt metadata

### 2. Format String Vulnerabilities
- Arbitrary memory reads and writes
- GOT/PLT manipulation
- Global variable modification

### 3. Return-Oriented Programming (ROP)
- Bypassing execution prevention
- Code reuse attacks

### 4. Heap Exploitation
- Heap layout manipulation
- Function pointer overwrites
- Chunk corruption

## Disclaimer

The information provided in this repository is for educational and research purposes only. Users are responsible for ensuring they have proper authorization before testing these techniques on any systems.


