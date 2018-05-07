---
title: "Fuzzing binutils, Part 1: Out-of-Bounds Read in libbfd"
layout: post
category: bug-hunting
tags: bug-hunting fuzzing binutils vulnerability-research
---

A few weeks ago, I finally got around to trying out [American Fuzzy Lop](http://lcamtuf.coredump.cx/afl/) for this first time. From the afl home page:

> "American fuzzy lop is a security-oriented fuzzer that employs a novel type of compile-time instrumentation and genetic algorithms to automatically discover clean, interesting test cases that trigger new internal states in the targeted binary."

I started out with a few fuzzing runs against a couple of projects downloaded from Github to get familiar with the CLI tool. After I had gotten the hang of things, I decided I wanted to try to find a bug in a core Linux utility and decided I would fuzz the GNU binutils set of tools. This resulted in a few interesting crashes that eventually led me to discover a bug in the version of the Binary File Descriptor library (libbfd) included with the target version of binutils. 

- **Target**: binutils 2.24/libbfd-2.24 ([Download](https://ftp.gnu.org/gnu/binutils/binutils-2.24.tar.gz))
- **Compiled With**: gcc (Ubuntu 5.4.0-6ubuntu1~16.04.5) 5.4.0 20160609

*Note*: The bug described in this post has been fixed in newer version of binutils and was likely discovered in the same manner. During my research for this project I came across a few references to others who had fuzzed binutils and found issues in libbfd. I figured I would be re-discovering old bugs, but I was mostly interested in the experience I could gain from going through the process.



### A Little About the Binary File Descriptor Library and S-records
The [Binary File Descriptor](ftp://ftp.gnu.org/old-gnu/Manuals/bfd-2.9.1/html_mono/bfd.html#SEC1) library, libbfd, provides applications with a common interface to the parts of an object file. It is primarily used by tools like binutils and GDB. All operations on the target object file are performed as methods to the BFD. It is composed of two parts: the front end and back ends. The front-end is the interface provided to the user. The back-ends provide calls that the front-ends use to provide that interface. For example, there are back-ends for ELF, COFF, and other binary formats.

The bug found in this case occurs in the back-end for the [S-record](https://en.wikipedia.org/wiki/SREC_(file_format)) file format, also known as SREC.

> Motorola S-record is a file format, created by Motorola, that conveys binary information in ASCII hex text form.

The format is defined as:

```
S<Type><Byte Count><Address><Data><Checksum>

1. Record type: two characters, an uppercase "S" (0x53) then a numeric digit 0 to 9, defining the type of record.
2. Byte count: two hex digits, indicating the number of bytes (hex digit pairs) that follow in the rest of the record (address + data + checksum). This field has a minimum value of 3 for 16-bit address field plus 1 checksum byte, and a maximum value of 255 (0xFF).
3. Address: four / six / eight hex digits as determined by the record type. The address bytes are arranged in big endian format.
4. Data: a sequence of 2n hex digits, for n bytes of the data. For S1/S2/S3 records, a maximum of 32 bytes per record is typical since it will fit on an 80 character wide terminal screen, though 16 bytes would be easier to visually decode each byte at a specific address.
5. Checksum: two hex digits, the least significant byte of ones' complement of the sum of the values represented by the two hex digit pairs for the byte count, address and data fields. 
```


### Fuzzing
I downloaded binutils-2.24 from the GNU mirror and compiled it using the afl wrapper of gcc that provides the instrumentation for afl. I then began by running afl against the `objdump` binary. For a test case, I chose the stock binary for `xgd-user-dir` provided in Ubuntu Server 16.04, chosen mostly for it's small file size. I put this binary in the testcase directory and ran afl with the following command. I chose to use `objdump`'s '-s' flag, which reads the full contents of all sections requested


```
afl-fuzz -i testcases/ -o findings/ ./objdump -s @@
``` 


After running for about an hour there were around 20 unique crashes found. I then ran afl using it's crash triage mode with a tailored selection of the crashes found in the first run. This produced another small set of unique crashes. From the final set, I chose one from each run that resulted in a SIGSEGV for testing.


### The Crash
The crash file produced by afl used for debugging is named `flip06`.

**flip06 hexdump**:

```
0x00000000  5331 3031 3131 3131 3131 3131 3131 316e  S10111111111111n                                                  
0x00000010  6e6e 6e6e 0080 0100 6e6e 1944 475f 247b  nnnn....nn.DG_${                                                  
0x00000020  317d 5f00 8000 006e 7f19 4447 5f24 7b31  1}_....n..DG_${1                                                  
0x00000030  7d5f 4449
```

I ran `objdump` in gdb , using the -s flag and providing `flip06` as the input file. Starting execution without setting a breakpoint resulted in signal SIGSEGV at fault address `0xbd1000`. The backtrace shows the instruction pointer was last executing function `srec_scan` in source file bfd/srec.c. 

Execution was in this section of source file `objdump-2.24/binutils-2.24/bfd/srec.c`


```
554             sec->filepos = pos;
555           }
556 
557         while (bytes > 0)
558           {
559             check_sum += HEX (data);
560             data += 2;
561             bytes--;
562           }
563         check_sum = 255 - (check_sum & 0xff);
```


## Source Code Analysis
Since the crash occurs in `srec_scan()`, I focused my attention there first. The function definition begins at line 296 of file *binutils-2.24/bfd/srec.c*.


### srec_scan()
`srec_scan()` declares some local variables and calls `bfd_seek()`, which sets the afbd->where pointer to the beginning of the file IO vector. abfd->where keeps track of the state of the file that was opened. Next, the code reads a byte from the beginning of the current position with function `srec_get_byte()`. This function calls `bfd_bread()` internally, which reads from the `iovec` structure containing the IO vector for the supplied input file. The call to `bfd_bread` in `srec_get_byte` increments abfd->where by the number of bytes read (1 in this case). It then checks this byte to check if it is one of 3 values ("S","\r","\n"), resulting in variable `sec` being set to NULL if it is not. Finally, a switch statement begins, testing against the byte read from abfd structure.


```
297 srec_scan (bfd *abfd)
298 {
299   int c;
300   unsigned int lineno = 1;
301   bfd_boolean error = FALSE;
302   bfd_byte *buf = NULL;
303   size_t bufsize = 0;
304   asection *sec = NULL;
305   char *symbuf = NULL;
306 
307   if (bfd_seek (abfd, (file_ptr) 0, SEEK_SET) != 0)
308     goto error_return;
309 
310   while ((c = srec_get_byte (abfd, &error)) != EOF)
311     
312       /* We only build sections from contiguous S-records, so if this
313      is not an S-record, then stop building a section.  */
314       if (c != 'S' && c != '\r' && c != '\n')
315     sec = NULL;
316 
317       switch (c)
```


The switch block has a case for the value 'S', which is present in our test case at offset 0x00. This leads execution to the the code block below. A call is made to `bfd_bread()` at line 467 and three bytes are read from the `abfd->iovec` structure and written into char array `hrd[]`. In our case, the three bytes would be 0x31,0x30,and 0x31 ('1','0','1'), since abfd->where has been pushed forward to offset 0x01 by `bfd_bread()`. 


```
454     case 'S':
455       {
456         file_ptr pos;
457         char hdr[3];
458         unsigned int bytes;
459         bfd_vma address;
460         bfd_byte *data;
461         unsigned char check_sum;
462 
463         /* Starting an S-record.  */
464 
465         pos = bfd_tell (abfd) - 1;
466 
467         if (bfd_bread (hdr, (bfd_size_type) 3, abfd) != 3)
468           goto error_return;
469 
470         if (! ISHEX (hdr[1]) || ! ISHEX (hdr[2]))
471           {
472         if (! ISHEX (hdr[1]))
473           c = hdr[1];
474         else
475           c = hdr[2];
476         srec_bad_byte (abfd, lineno, c, error);
477         goto error_return;
478           }
479 
480         check_sum = bytes = HEX (hdr + 1);
```


### Detour: Following a Macro Chain
In the final line (480) of the code excerpt above, `hdr + 1` is passed as an argument to the macro HEX and the result is stored in unsigned int `bytes` and unsigned char `check_sum`. HEX is defined as:

```
#define HEX(buffer) ((NIBBLE ((buffer)[0])<<4) + NIBBLE ((buffer)[1]))
``` 

It takes the first value pointed to in the array and passes it to the NIBBLE macro, the result of which is left-shifted by 4. It also passes the next value in the array to NIBBLE. The results of these two expressions are added together and returned. 

NIBBLE is defined below. This macro takes the value passed to it and passes it to another macro, `hex_value`, which uses it as an index into a buffer that represents the ASCII charset, except only certain values are actually defined. Anything outside of these values is represented as a 'bad' byte. The only 'good' values are the hex values for the ASCII characters in the hex keyspace [0-1] and [A-F]. NIBBLE returns the value that was indexed.


```
#define NIBBLE(x)  hex_value(x)
```


Returning to where we left off, line 480 passes `hdr + 1` to `HEX`. Since `hdr` in this use is a pointer to the first value ('1'), `hdr + 1` increments the pointer value so that it points to the second value in the array and this is what is passed to `HEX`. Since '0' is a valid hex character, NIBBLE returns the numeric representation of the char. This value is left-shifted by 4, leaving it at 0. The next value in the buffer('1') is also passed to NIBBLE and it's decimal value is returned (1). Finally, the sum of the result of these expressions is returned.


### Back To srec_scan
For this test case, the statement at line 480 breaks down to `check_sum = bytes = (0 + 1)`. *Note: `bytes` is an unsigned int and `check_sum` is an unsigned char*.

With `bytes` set to 1, the if statement on line 481 evaluates to true since `bufsize` equals 0. The code in this block calls `bfc_malloc()` to allocate a new buffer of size `bytes * 2`. When this inner code segment is finished, execution continues at line 491 with a call to `bfd_bread()` which reads `bytes * 2` bytes from the current position of the IO vector in the bfd structure. For our test case, the two bytes (1 * 2) read are '11' since the position is at offset 0x5 in our input file. This data is stored in the buffer where memory was just allocated, `buf`.


```
481         if (bytes * 2 > bufsize)
482           {
483         if (buf != NULL)
484           free (buf);
485         buf = (bfd_byte *) bfd_malloc ((bfd_size_type) bytes * 2);
486         if (buf == NULL)
487           goto error_return;
488         bufsize = bytes * 2;
489           }
490 
491         if (bfd_bread (buf, (bfd_size_type) bytes * 2, abfd) != bytes * 2)
492           goto error_return;
 ```


Next, `bytes` is decremented by 1, making it's value 0. `address` is set to 0 and `data` is assigned the value of `buf`, which points to the newly allocated buffer that contains the two bytes that were read on line 491. Finally, a switch statement begins that tests the value of `hdr[0]`. As stated above, `hdr[]` contains the values ['1','0','1'].


 ```
494         /* Ignore the checksum byte.  */
495         --bytes;
496 
497         address = 0;
498         data = buf;
499         switch (hdr[0])
```


`hdr[0]` is '1', so execution continues at line 520. `check_sum` is incremented by the value returned by `HEX (data)`. The value of `address` is left-shifted 8 bytes and bitwise OR'ed with the value returned by `HEX (data)`, effectively performing the left-shift on the return value of `HEX` since `address` equals 0. The result of this expression is saved to `address`. The pointer `data` is incremented by 2. The previous three statements are repeated again, this time using the updated value of address.


```
520         case '1':
521           check_sum += HEX (data);
522           address = (address << 8) | HEX (data);
523           data += 2;
524           check_sum += HEX (data);
525           address = (address << 8) | HEX (data);
526           data += 2;
527           bytes -= 2;
```


In this case, the value returned by the statement at line 522 is 0x00000011 since the values used by `HEX` are '1' and '1'. The statement at line 523 then increments the pointer `data` past the end of the buffer that was previously allocated (recall that only 2 bytes were allocated at line 485). This means the call to `HEX (data)` at line 525 performs it's operations using the first two bytes of the next chunk. `data` is then incremented by two again and `bytes` is decremented by 2. Since `bytes` had been previously decremented to 0 and it is of type `unsigned int`, this results in `bytes` containing the value 0xfffffffe.

The code then reaches the code block below. `sec`, which is a structure of type `asection`, is still set to NULL, so exection jumps to line 536:


```
529         if (sec != NULL
530             && sec->vma + sec->size == address)
531           {
532             /* This data goes at the end of the section we are
533                currently building.  */
534             sec->size += bytes;
535           }
536         else
537           {
538             char secbuf[20];
539             char *secname;
540             bfd_size_type amt;
541             flagword flags;
542 
543             sprintf (secbuf, ".sec%d", bfd_count_sections (abfd) + 1);
544             amt = strlen (secbuf) + 1;
545             secname = (char *) bfd_alloc (abfd, amt);
546             strcpy (secname, secbuf);
547             flags = SEC_HAS_CONTENTS | SEC_LOAD | SEC_ALLOC;
548             sec = bfd_make_section_with_flags (abfd, secname, flags);
549             if (sec == NULL)
550               goto error_return;
551             sec->vma = address;
552             sec->lma = address;
553             sec->size = bytes;
554             sec->filepos = pos;
555           }
```


The code above constructs a section object with `bfd_make_section_with_flags()`, saving it to `sec`. If this is successful and `sec` is no longer NULL, the value of `address`, which had been corrupted in the code described above, is assigned to `sec->vma` and `sec->lma`. The `asection` structure is defined in binutils-2.24/bfd/bfd-in2.h. The relevant variables, `vma` and `lma` are shown below.


```
  /* End of internal packed boolean fields.  */

  /*  The virtual memory address of the section - where it will be
      at run time.  The symbols are relocated against this.  The
      user_set_vma flag is maintained by bfd; if it's not set, the
      backend can assign addresses (for example, in <<a.out>>, where
      the default address for <<.data>> is dependent on the specific
      target and various flags).  */
  bfd_vma vma;

  /*  The load address of the section - where it would be in a
      rom image; really only used for writing section header
      information.  */
  bfd_vma lma;
``` 


Execution now arrives at the location where the crash occurs. At this point, `bytes` = 0xfffffffe, so it is *much* greater than 0. This loop continues incrementing the `data` pointer and reading from it with the `HEX` macro until it reads out of bounds, causing an invalid memory access error. In the process, `check_sum` is also overflowed and equals 87 at the time of the segfault.


```
557         while (bytes > 0)
558           {
559             check_sum += HEX (data);
560             data += 2;
561             bytes--;
562           }
``` 


## Wrapping Things Up
The bug itself occurs because user-controlled data is used to determine the size of a buffer that is allocated. Two operation are present that decrement this value by a total of 3 before it is used as a counter in a loop that reads from this buffer. It is possible to provide an input that causes this value to be low enough that an integer underflow occurs. This causes the loop that reads from the buffer to read far past the end of the allocated space, which eventually causes an address boundary error when it reads past the end of the heap.

I really enjoyed analyzing this bug and learned a lot of new things along the way. I became more familiar with GDB functionality and learned a bit about C macros. Overall, this was a fun project that was worth the hours of mind-melting focus. This will likely be the first part in a series since there are probably other bugs just waiting to be found :)


### References
3. [binutils-2.24](https://ftp.gnu.org/gnu/binutils/binutils-2.24.tar.gz)
1. [BFD documentation](ftp://ftp.gnu.org/old-gnu/Manuals/bfd-2.9.1/html_mono/bfd.html#SEC1)
2. [S-Records Wikipedia page](https://en.wikipedia.org/wiki/SREC_(file_format))


## BONUS: Triggering a NULL Dereference

If the input provided begins with 'S100' (as opposed to 'S101', as shown above), it is possible to skip the code block between line 481-489, which performs the allocation of memory for `buf`.

```
481         if (bytes * 2 > bufsize)
482           {
483         if (buf != NULL)
484           free (buf);
485         buf = (bfd_byte *) bfd_malloc ((bfd_size_type) bytes * 2);
486         if (buf == NULL)
487           goto error_return;
488         bufsize = bytes * 2;
489           }
```

If this occurs, then `buf` still equals NULL. The address pointed to by `buf` is saved in `data` at line 498 and the next time the macro `HEX` is called it attempts to access the value at index 0 of `data`, resulting in a NULL pointer dereference.

![NULL dereference]({{ base.url }}/assets/images/null-dereference.png)