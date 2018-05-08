---
title: "Reversing A Few Lines From srec_scan(): Notes"
layout: post
category: reverse-engineering
tags: reversing bug-hunting binutils vulnerability-research
---

I decided to go through the process of analyzing and documenting the assembly for 'srec_scan()' in *binutils-2.24/bfd/srec.c* to gain a better understanding of everything that was happening under the hood. I figured this would be a good way to get more practice with assembly and reverse engineering, since I had the source code available and would be able to follow along with it. This is the same function that contains the bug I wrote about in my [previous post](http://hypercrux.com/bug-hunting/2018/01/19/Fuzzing-binutils-Pt1-OOB-Read/). The code does some interesting things, so there was exposure to some new instructions and constructs.

While I was going through this process, I came upon a block of assembly that corresponded with the section of source code for a case in a switch statement. I could kind of recognize the assembly as corresponding with this block of source, but the compiler had done some things that really confused me upon first look. I know that compilers sometimes do things to optimize certain operations and this results in the assembly not matching the source code "1:1", but I'm not familiar enough to know exactly when this is done or what the results look like. I didn't feel comfortable moving on without understanding what was going on here, so I decided to go through the assembly line-by-line, taking notes on each one to keep track of values and results. After a few hours of doing this, I had finally gone through the entire thing and understood what the compiler had done and why. 

This turned out to be one of the most productive learning exercises I have gone through. I had to spend some time digging through the Intel Developer's Manuals to get a better understanding of certain instructions, learned about jump tables (super cool!), and improved my ability to keep track of values and results in assembly. One of the most challenging things when first getting started learning assembly is learning to keeping of values being moved around and changed, so it was good practice.

Going through ASM this way helped me a ton and I think it could help others who are just starting out as well.  When I was done with this piece of code, I had some pretty decent notes that explained exactly what was happening and how that correlated with the source code. I realized these might be useful to someone else who's learning RE, so I decided to write this post and include them. 

Before we begin, here are some things you'll want to have when doing this kind of work:

1. Reference material - Intel Developer's Manual 1-3, Google
2. Text editor you feel comfortable taking notes in
3. Pen and paper (you'll want to have this too, trust me)
4. Disassembler/debugger you feel comfortable with
5. Lots of patience

*Note: I say work with a debugger you're comfortable with, but if you're not comfortable with any yet, spend some time there first.*

Let's dig in.


## srec_scan() in binutils-2.24/bfd/srec.c (lines 521-527)

**Starting Values**:
`  
1. `address`= 0
2. `check_sum` = 1
3. `data` = ptr to a buffer, 2 bytes in size, that contains string '11'
4. `bytes` = 0

**Source Code (lines 521-527)**:  

```
case '1':
	check_sum += HEX (data);
	address = (address << 8) | HEX (data);
	data += 2;
	check_sum += HEX (data);
	address = (address << 8) | HEX (data);
	data += 2;
	bytes -= 2;
```

**Macros**:

```
#define HEX(buffer) ((NIBBLE ((buffer)[0])<<4) + NIBBLE ((buffer)[1]))
#define NIBBLE(x)    hex_value(x)
#define hex_value(c)	((unsigned int) _hex_value[(unsigned char) (c)])
```

`_hex_value` is an array of size 255. Indices 0x30-0x39 and 0x41-0x47 return 0-9 and 10-16, respectively. All other indices return the value 0x63.

**Assembly**:  

```
1   movzx edx, byte [rbp]
2   add rbp, 4
3   lea r14d, [r9 - 2]
4   movzx r10d, byte [rdx + _hex_value]
5   movzx edx, byte [rbp - 3]
6   movzx ecx, byte [rdx + _hex_value]
7   movzx edx, byte [rbp - 2]
8   mov edi, r10d
9   shl edi, 4
10  movzx esi, byte [rdx + _hex_value]
11  movzx edx, byte [rbp - 1]
12  movzx edx, byte [rdx + _hex_value]
13  lea r8d, [rcx + rdx]
14  add r12d, r8d
15  mov r8d, r10d
16  lea r10d, [rdi + rcx]
17  shl r8d, 4
18  mov rcx, qword [rsp]
19  add r8d, r12d
20  or r10, rax
21  mov r12d, esi
22  shl esi, 4
23  shl r12d, 4
24  shl r10, 8
25  add edx, esi
26  add r12d, r8d
27  or r10, rdx

```

1. `movzx edx, byte [rbp]`
	- rbp contains the address to the beginning of `data`, where 2 bytes are allocated
	- 'data' contains '11'
	- edx now contains the first byte from 'data'
	- the first byte in 'data' is '1'
	- edx == 0x31

2. `add rbp, 0x4`
	- the address at rbp (pointing to 'data') is increased by 4.
	- rbp now points 2 bytes past the end of the memory allocated for `data`
	- compiler combines the two 'data+=2' instructions from the source code into a single `data`+=4

      ```
      |.'1'.|.'1'.|-----|-----|-----|
         ^		           ^
        rbp @	               rbp after
        start                 rbp+0x4
      ```

3. `lea r14d, dword [r9-2]`
    - r9 = 0 (`bytes` value is kept in a register)
	- subtract 2 from 'bytes'
	- 'bytes' is now equal to 0xfffffffe (4294967294)
	- r14d == 0xfffffffe

4. `movzx r10d, byte [rdx+_hex_value]`
	- rdx == 0x31 ('1')
	- read a byte at offset 0x31 of `_hex_value` array (HEX use of NIBBLE 1)
	- offset 0x31 of `_hex_value` returns the numeric value, 1
	- r10d == 0x1

5. `movzx edx, byte [rbp-3]`
	- rbp-3 reads a byte 3 bytes behind where rbp currently points (rbp was increased by 4 before this)
	- this reads the byte that was after the first byte of 'data'
	- this would be '1'
	- edx == 0x31

      ```
                     [rbp-3]--------------.
                        |  		    |
                        V  		    |
      	 |.'1'.|.'1'.|-----|-----|-----|
      	    ^		            ^	
      	  rbp @	                 rbp after
                start                   rbp+0x4
      ```

6. `movzx ecx, byte [rdx+_hex_value]`
	- rdx == 0x31	
	- read a byte at offset 0x31 of _hex_value array (HEX use of NIBBLE 2)
	- offset 0x31 of _hex_value is the returns the numeric value, 1
	- ecx == 0x1

7. `movzx edx, byte [rbp-2]`
	- rbp-3 reads a byte 2 bytes behind where rbp currently points (rbp was increased by 4 before this)
	- this reads the byte that was after the second byte of 'data'
	- rbp points to a buffer that was only allocated 2 bytes of memory
	- byte [rbp-2] reads outside of this buffer (on the heap, since this was alloc'ed)
	- this means it likely reads from the next heap chunk
	- edx == ??

      ```
                     	      [rbp-2]-------.
                              |           |
                              V           |
      	 |.'1'.|.'1'.|--?--|--?--|-----|
      	    ^                       ^	
                rbp @	                 rbp after
                start                   rbp+0x4
      ```

8. `mov edi, r10d`
	- r10d == 0x1
	- edi == 0x1

9. `shl edi, 0x4`
	- before: edi == 0x01
	- after: edi == 0x10
	- NIBBLE(buf[0])<<4) in HEX
	- edi == 0x10

10. `movzx esi, byte [rdx+_hex_value]`
	- rdx == ??	
	- read a byte at offset ?? of _hex_value array (HEX use of NIBBLE 3)
	- offset ?? of _hex_value most likely returns 0x63 since any value not between 0x30-0x39 or 0x41-0x46 returns this
	- esi == 0x63 (most likely)


11. `movzx edx, byte [rbp-1]`
	- rbp-3 reads a byte 1 byte behind where rbp currently points (rbp was increased by 4 before this)
	- this reads the byte at the previous address 'data'+3
	- rbp points to a buffer that was only allocated 2 bytes of memory
	- byte [rbp-1] reads outside of this buffer (on the heap, since this was alloc'ed)
	- this means it likely reads
	- edx == ??

       ```
                      	            [rbp-1]-.
                                     |     |
                                     V     |
       	 |.'1'.|.'1'.|--?--|--?--|-----|
       	    ^                       ^	
                 rbp @	                 rbp after
                 start                   rbp+0x4
       ```

12. `movzx edx, byte [rdx+_hex_value]`
	- rdx == ??	
	- read a byte at offset ?? of _hex_value array (HEX use of NIBBLE 4)
	- offset ?? of _hex_value most likely returns 0x63 since any value not between 0x30-0x39 or 0x41-0x46 returns this
	- edx == 0x63 (most likely)


13. `lea r8d, dword [rcx+rdx]`
	- rcx + rdx == 0x1 + 0x63 = 0x64
	- rcx contains result of one of the NIBBLE's from first pair of HEX calls (that read inside the buffer)
	- possibly doing this as part of the increment of check_sum, if the result is the same in the end
	- r8d = 0x64


14. `add r12d, r8d`
	- r12d + r8d == 0x1 + 0x64
	- r12 = 0x65
	- possibly doing this as part of the increment of check_sum, if the result is the same in the end (r8 being check_sum)

15. `mov r8d, r10d`
	- r10d = 0x1, result of call to NIBBLE on one of first two bytes ['11']
	- r8d = 0x1

16. `lea r10d, dword [rdi+rcx]`
	- rdi + rcx = 0x10 + 0x1
	- result of `NIBBLE ((buf[0])<<4) + NIBBLE (buf[1])` in first pair of calls to HEX from source code
	- r10d = 0x11

17. `shl r8d, 0x4`
	- r8d = 0x1
	- r8d = 0x1<<4
	- second left-shift for call to HEX that reads inside the buffer ('11')
	- r8d = 0x10

18. `mov rcx, qword [rsp]`
	- this instruction is preparation for something that happens outside of this block

19. `add r8d, r12d`
	- r8d + r12d = 0x10 + 0x65
	- r8d = 0x75

20. `or r10d, rax`
	- r10d OR rax = 0x11 OR 0x00
	- rax was XOR'd with itself to clear it before the jump to this code block
	- this OR corresponds to instruction: `address = (address << 8) | HEX (data);`	
	- compiler skips the shift-left because it knows 'address' was set to 0 and 0<<8 = 0 ???
	- r10d = 0x11

21. `mov r12d, esi`
	- esi = 0x63
	- contains the result of the second pair of calls to HEX that read beyond the allocated buffer
	- r12d = 0x63

22. `shl esi, 0x4`
	- `esi <<4 = 0x63 <<4 = 0x630`
	- shift-left from the second pair of calls to HEX that read beyond the allocated buffer
	- esi = 0x630

23. `shl r12d, 0x4`
	- r12d <<4 = 0x63 <<4 = 0x630
	- shift-left from the second pair of calls to HEX that read beyond the allocated buffer
	- r12d = 0x630 
	
24. `shl r10d, 8`
	- `r10d <<8 = 0x11 <<8 = 0x1100`
	- r10d was previously OR'ed with the value of `address`, so it is 0x11
	- shift-left by 8 for instruction: `address = (address << 8) | HEX (data);`
	- `address` = 0x1100
	- r10d = 0x1100

25. `add esi, edx`
	- esi + edx = 0x630 + 0x63
	- corresponds to second pair of calls to HEX (results of which would eval to `(0x63<<4)+(0x63) = 0x693`
	- final result for second pair of HEX calls	
	- esi = 0x693

26. `add r12d, r8d`
	- r12d + r8d = 0x630 + 0x75
	- this is probably part of a group of operations that are incrementing check_sum
	- instructions are dispersed here and there, but I think this is because the result of incrementing check_sum are the same whether the increments are done in the order they appear in the source or not
	- r12d = 0x6a5

27. `or r10, rdx`
	- r10 OR rdx = 0x1100 OR 0x693
	- corresponds with second use of: `address = (address << 8) | HEX (data);` since address = 0x1100
	- r10 = 0x1793


**Souce Code Re-written**:

This is the same source code as above, rewritten to show the results of HEX to make things clearer.

```
# check_sum starts with value 0x1
check_sum += (0x10 + 0x1)       // check_sum now == 0x12 
address = 0<<8 | (0x10 + 0x1)   // address now == 0x11
data += 2                   
check_sum += (0x630 + 0x63)     // check_sum now == 0x11+0x693 = 0x6a5
address = 0x11<<8 | 0x693       // address = 0x1793
data += 2
bytes -= 2                      // bytes now == 0xfffffffe (4294967294)
```