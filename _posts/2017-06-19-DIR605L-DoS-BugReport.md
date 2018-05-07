---
title: "CVE-2017-9675: D-Link DIR-605L Denial of Service Discovery+Analysis"
layout: post
category: vuln-report
tags: bug-hunting dlink cve exploit
---

With the wave of IoT/embedded device security incidents that struck last year, I became interested in looking for vulnerabilities in some of the devices I had laying around and in use around the house. Because I’m aware of the security and privacy issues most of these devices present, I don’t own many to begin with. I chose the D-Link DIR-615L out of the pile of old routers I had in a box mostly on a whim and it turned out to be a great place to start. 

After a few weeks of testing, I discovered a bug that allowed me to restart the router by sending a single GET request to it's web server. I decided to focus on this bug and attempt to identify it's location and root cause. With only a limited knowledge of C and MIPS assembly, it turned out to be a good challenge and learning experience. Overall, it was a fun project and I was able to get my first CVE assigned for this vulnerability. This was also my first time reporting a vulnerability to a vendor and I was really pleased to have gotten such a quick responses and remediation from D-Link. 

Below is the report I sent D-Link containing my findings and theories of the potential cause of the bug. Now that a patch has been released, I hope to compare the updated executable to the vulnerable one and identify the exact location of the patch and the fix that was applied. There will be a follow-up post in the near-future describing the results of that analysis. 

## DIR-605L Denial of Service via HTTP GET
While attempting to access known files in the web root directory via URL in the browser, the response from the server hung on a request to http://192.168.1.1/common/. I noticed the router was rebooting/resetting itself: connectivity was lost completely and the system LEDs flashed on and off the way they do during boot. This behavior was only triggered when the trailing '/' at the end of the directory was included. Further testing revealed that the crash was limited to GET requests; HEAD requests would result in an empty 200 OK response from the server, but no crash. All of this led me to believe the bug that was causing the crash was located somewhere in the Boa web server. 

### Details
- **Device**: D-Link DIR-605L, Model B
- **Vulnerable Firmware Versions**: 2.08UIB01 and prior releases. Fixed in 2.08UIBETA01.
- **Attack Vector**: Unauthenticated HTTP GET request
- **Impact**: Denial of service
- **CVE**: CVE-2017-9675

### PoC
```
curl http://192.168.1.1/common/
```

### Static Code Analysis
I downloaded the matching version of the Boa web server from it's web site http://www.boa.org/. The "Server" string in responses from the server on the router indicated it was using version 0.94.14rc21. I do know it is a modified version, built with a custom library called `apmib.so` and possibly other modifications, but this was as close as I was going to get to the source. Some details on the boa binary present on the router:

```
hyper@ubuntu:~/squashfs-root-0$ mips-linux-gnu-objdump -f bin/boa

bin/boa:     file format elf32-tradbigmips
architecture: mips:3000, flags 0x00000102:
EXEC_P, D_PAGED
start address 0x00407400
```

Since the bug was only triggered by GET requests, I assumed the bug occured somewhere in one of the functions that handles GETs, and only in those that handle GETs for directories. Furthermore, only requests for directories with the trailing '/' included, meaning functions that modified or used the URL string could be likely culprits.

After extracting the downloaded archive, I began reading through the source code looking for files that would likely contain code for handling requests. Surely enough, there was a file called request.c in the src/ directory, so I began there. This file contains many of the functions that handle the processing of requests. Most of them operate on a `request` struct, which is defined in src/globals.h. There are member variables that store the requested pathname and the file descriptor for the opened file, among others.

#### process_requests()

Processing of requests begins, naturally, in the function `process_requests()`. If there are pending requests on the queue, another function named `get_request()` is called to fetch a request from the queue. This function calls some others to perform some basic sanitization and processing before returning a pointer to the initialized req struct. If everything comes back clean after a couple of checks for timeouts and errors, a switch..case statement begins for iteratively processing requests.

```c
if (retval == 1) {
            switch (current->status) {
            case READ_HEADER:
            case ONE_CR:
            case ONE_LF:
            case TWO_CR:
                retval = read_header(current);
                break;
            case BODY_READ:
                retval = read_body(current);
                break;
            case BODY_WRITE:
                retval = write_body(current);
                break;
            case WRITE:
                retval = process_get(current);
                break;
            case PIPE_READ:
                retval = read_from_pipe(current);
                break;
            case PIPE_WRITE:
                retval = write_from_pipe(current);
                break;
            case IOSHUFFLE:
            [...]
            }
```

#### process_requests() -> read_header()

The first call is to read.c:`read_header(current)`. 'current' is a pointer to the request struct being operated on. After performing some operations to read the head of the request and setting some of the flags used in the switch statement above, the pointer to 'current' is passed along to the function request.c:`process_logline()` located in request.c. 

Description of the function from code comments:
```c
/*
 * Name: process_logline
 *
 * Description: This is called with the first req->header_line received
 * by a request, called "logline" because it is logged to a file.
 * It is parsed to determine request type and method, then passed to
 * translate_uri for further parsing.  Also sets up CGI environment if
 * needed.
 */
```

request.c:`process_logline()` parses the request URI and error handling for things such as malformed requests or invalid URI lengths, among others. This functions caught my attention since it was working on the request URI; since the bug is only triggered in requests to functions that included the trailing '/', I thought it might have something to do with the URI/pathname parsing functions. After some time going over the code, I concluded that the bug was not present in this function and moved on.


Once `process_logline()` returns back to `read_header()`, the next function that operates on the current request is request.c:`process_header_end()`, since req->status has been set to BODY_READ previously. Code snippet from `read_header()`:

```c
            } else {
                if (process_logline(req) == 0)
                    /* errors already logged */
                    return 0;
                if (req->http_version == HTTP09)
                    return process_header_end(req);
            }
            /* set header_line to point to beginning of new header */
            req->header_line = check;
        } else if (req->status == BODY_READ) {
#ifdef VERY_FASCIST_LOGGING
            int retval;
            log_error_time();
            fprintf(stderr, "%s:%d -- got to body read.\n",
                    __FILE__, __LINE__);
            retval = process_header_end(req);
#else
            int retval = process_header_end(req);
#endif
            /* process_header_end inits non-POST CGIs */
```


#### process_requests() -> read_header() -> process_header_end()

As the description in the code comments indicate, the request.c:`process_header_end()` function performs some final checks on the request before calling get.c:`init_get()`. Most of these tests check req->request_uri for invalid characters or malformed input. I took a look at these functions to see if the bug was located in one of them, but this does not appear to be the case.  


```c
/*
 * Name: process_header_end
 *
 * Description: takes a request and performs some final checking before
 * init_cgi or init_get
 * Returns 0 for error or NPH, or 1 for success
 */

int process_header_end(request * req)
{
    if (!req->logline) {
        log_error_doc(req);
        fputs("No logline in process_header_end\n", stderr);
        send_r_error(req);
        return 0;
    }

    /* Percent-decode request */
    if (unescape_uri(req->request_uri, &(req->query_string)) == 0) {
        log_error_doc(req);
        fputs("URI contains bogus characters\n", stderr);
        send_r_bad_request(req);
        return 0;
    }

    /* clean pathname */
    clean_pathname(req->request_uri);

    if (req->request_uri[0] != '/') {
        log_error("URI does not begin with '/'\n");
        send_r_bad_request(req);
        return 0;
    }

    [...]

    if (translate_uri(req) == 0) { /* unescape, parse uri */
        /* errors already logged */
        SQUASH_KA(req);
        return 0;               /* failure, close down */
    }
    [...]

    if (req->cgi_type) {
        return init_cgi(req);
    }

    req->status = WRITE;

    return init_get(req);       /* get and head */
}
```

After all checks have been performed, there is a check to see if 'req->cgi_type' has been initialized. Since nothing has set this variable, the check fails and instead 'req->status' is set to WRITE and `init_get()`is called, with it's return value being used as `process_header_end()`'s return value.

#### process_requests() -> read_header() -> process_header_end() -> init_get()

From the description of get.c:`init_get()` below, I could tell the request would follow this path since it is a non-script GET request.
```c
/*
 * Name: init_get
 * Description: Initializes a non-script GET or HEAD request.
 */

int init_get(request * req)
{
    int data_fd, saved_errno;
    struct stat statbuf;
    volatile unsigned int bytes_free;

    data_fd = open(req->pathname, O_RDONLY);
    saved_errno = errno;        /* might not get used */

    [...]

    fstat(data_fd, &statbuf);
```
An integer variable is declared to hold the resulting file descriptor for the opened path, and a stat struct called statbuf. statbuf holds information about the status of the opened files. It is initalized with a call to `fstat()`.

After a test to see if the path was opened successfully, there is check to see if it is a directory. This would evaluate true in the case of the request that triggers the bug. The opened file descriptor is closed and then a check is performed to see if the final character of the request is *not* a '/'. This would evaluate false, so the code that follows would be skipped. 
```c
    if (S_ISDIR(statbuf.st_mode)) { /* directory */
        close(data_fd);         /* close dir */

        if (req->pathname[strlen(req->pathname) - 1] != '/') {
            char buffer[3 * MAX_PATH_LENGTH + 128];
            unsigned int len;

            [...]
        }

        data_fd = get_dir(req, &statbuf); /* updates statbuf */

        if (data_fd < 0)      /* couldn't do it */
            return 0;           /* errors reported by get_dir */
        else if (data_fd == 0 || data_fd == 1)
            return data_fd;
        /* else, data_fd contains the fd of the file... */
    }
}
```

The next segment of code that would be executed begins at the call to `get_dir()`.

#### process_requests() -> read_header() -> process_header_end() -> init_get() -> get_dir()

At this point, I believe get.c:`get_dir()` is likely to contain the function call that causes the crash since everything that has happened up until this point also applies to requests for non-directories. No requests for existing regular files trigger the crash, meaning it must be in the functions related to opening directories. 

```c
/*
 * Name: get_dir
 * Description: Called from process_get if the request is a directory.
 * statbuf must describe directory on input, since we may need its
 *   device, inode, and mtime.
 * statbuf is updated, since we may need to check mtimes of a cache.
 * returns:
 *  -1 error
 *  0  cgi (either gunzip or auto-generated)
 *  >0  file descriptor of file
 */

int get_dir(request * req, struct stat *statbuf)
{

    char pathname_with_index[MAX_PATH_LENGTH];
    int data_fd;

    if (directory_index) {      /* look for index.html first?? */
    
    [...]
```

The function first checks for an index.html file in the requested directory. Since this would be false (no file named index.html exists in the requested directory), execution would skip to the segment of code below. 

*Note*: 'dirmaker' is a pointer to a char array that is initialized with the DirectoryMaker value configured in boa.conf. After checking what this was set to on the router via telnet, I saw that it was configured to use '/usr/lib/boa/boa_indexer', which turns out to be a non-existent file on the router. This may or may not be the cause of the bug, as I'll explain in the following section.

```c
    /* only here if index.html, index.html.gz don't exist */
    if (dirmaker != NULL) {     /* don't look for index.html... maybe automake? */
        req->response_status = R_REQUEST_OK;
        SQUASH_KA(req);

        /* the indexer should take care of all headers */
        if (req->http_version != HTTP09) {
            req_write(req, http_ver_string(req->http_version));
            req_write(req, " 200 OK" CRLF);
            print_http_headers(req);
            print_last_modified(req);
            req_write(req, "Content-Type: text/html" CRLF CRLF);
            req_flush(req);
        }
        if (req->method == M_HEAD)
            return 0;

        return init_cgi(req);
        /* in this case, 0 means success */
    } else if (cachedir) {
        return get_cachedir_file(req, statbuf);
    } else {                    /* neither index.html nor autogenerate are allowed */
        send_r_forbidden(req);
        return -1;              /* nothing worked */
    }
}
```

In this block, there is an inner block that writes the HTTP 200 response that the server replies with; at the end of this block there is a check to see if the request method was HEAD; if it is, the function returns 0. This is where the function stops when we send a HEAD request and the crash does not occur. If the method was not HEAD, the block returns the return of `init_cgi()`.


#### process_requests() -> read_header() -> process_header_end() -> init_get() -> get_dir() -> init_cgi()

As the code snippet below shows, `init_cgi()` begins by declaring a few variables for later use. There is a check to see if req->cgi_type has been set; since it has not, this is skipped. The next section of code contains a check to see if the final character in req->pathname is equal to '/' and that req->cgi_type has not been set. This evaluates true, which sets use_pipes to 1 and an unnamed pipe is opened, it's read and write fd's stored in pipes[].

```c
int init_cgi(request * req)
{
    int child_pid;
    int pipes[2];
    int use_pipes = 0;

    SQUASH_KA(req);

    if (req->cgi_type) {
        if (complete_env(req) == 0) {
            return 0;
        }
    }
    DEBUG(DEBUG_CGI_ENV) {
        int i;
        for (i = 0; i < req->cgi_env_index; ++i)
            log_error_time();
            fprintf(stderr, "%s - environment variable for cgi: \"%s\"\n",
                    __FILE__, req->cgi_env[i]);
    }

    /* we want to use pipes whenever it's a CGI or directory */
    /* otherwise (NPH, gunzip) we want no pipes */
    if (req->cgi_type == CGI ||
        (!req->cgi_type &&
         (req->pathname[strlen(req->pathname) - 1] == '/'))) {
        use_pipes = 1;
        if (pipe(pipes) == -1) {
            log_error_doc(req);
            perror("pipe");
            return 0;
        }
```

If there were no errors opening the pipe, fork() is called and it's return value saved. A switch statements then checks against the return value of fork(). If the fork was successful, case 0 is true and the next code to be executed (in the child process) would be the code block inside the if statement that checks 'use_pipes', since this would return true.

```c
child_pid = fork();
switch (child_pid) {
case -1:
    /* fork unsuccessful */
    /* FIXME: There is a problem here. send_r_error (called by
        * boa_perror) would work for NPH and CGI, but not for GUNZIP.  
        * Fix that. 
        */
    boa_perror(req, "fork failed");
    if (use_pipes) {
        close(pipes[0]);
        close(pipes[1]);
    }
    return 0;
    break;
case 0:
    /* child */
    reset_signals();

    if (req->cgi_type == CGI || req->cgi_type == NPH) {
        /* SKIPPED */
    }

    if (use_pipes) {
        /* close the 'read' end of the pipes[] */
        close(pipes[0]);
        /* tie CGI's STDOUT to our write end of pipe */
        if (dup2(pipes[1], STDOUT_FILENO) == -1) {
            log_error_doc(req);
            perror("dup2 - pipes");
            _exit(EXIT_FAILURE);
        }
        close(pipes[1]);
    }

```
As the comments in the code describe, the 'read' end of the previously opened pipe is closed and STDOUT is tied to the 'write' end of the pipe using `dup2()`. Finally, if all completes successfully, the next relevant segment of code would be the one below.

```c
        /*
         * tie STDERR to cgi_log_fd
         * cgi_log_fd will automatically close, close-on-exec rocks!
         * if we don't tie STDERR (current log_error) to cgi_log_fd,
         *  then we ought to tie it to /dev/null
         *  FIXME: we currently don't tie it to /dev/null, we leave it
         *  tied to whatever 'error_log' points to.  This means CGIs can
         *  scribble on the error_log, probably a bad thing.
         */
        if (cgi_log_fd) {
            dup2(cgi_log_fd, STDERR_FILENO);
        }

        if (req->cgi_type) {
            char *aargv[CGI_ARGC_MAX + 1];
            create_argv(req, aargv);
            execve(req->pathname, aargv, req->cgi_env);
        } else {
            if (req->pathname[strlen(req->pathname) - 1] == '/')
                execl(dirmaker, dirmaker, req->pathname, req->request_uri,
                      (void *) NULL);
```
Since req->cgi_type has not been set, the block after the if statement that checks it's value is skipped and instead the block following the else statement is executed. This checks if the final character in req->pathname is a '/'. In the case of the pathname that causes the crash, this would evaluate true. `execl()` is called like so:

```c
execl(dirmaker, dirmaker, req->pathname, req->request_uri, (void *) NULL);
```

## Potential Root Causes
### Incorrect Use of execl()
As mentioned above,'dirmaker' is a pointer to a char array that is initialized with the DirectoryMaker value configured in boa.conf (in the case of the router, this is '/usr/lib/boa/boa_indexer', a file that is not present on the system). This *could* be a potential cause of the crash. 

From http://pubs.opengroup.org/onlinepubs/7908799/xsh/execl.html:
> If the process image file is not a valid executable object, execlp() and execvp() use the contents of that file as standard input to a command interpreter conforming to system(). In this case, the command interpreter becomes the new process image.

Another might be the final argument which is passed to the function. 

From the `exec()` manpage:
>The const char *arg and subsequent ellipses in the execl(), execlp(), and execle() functions can be thought of as arg0, arg1, ..., argn.
> The  list  of  arguments  must be terminated by a null pointer, and, since these are variadic functions, this pointer must be cast (char *) NULL.

Looking at the call to `execl()` that is made shows that the final arguement is cast `(void *) NULL` instead of cast `(char *) NULL`. I haven't been able to find any documentation stating that this is absolutely required or what would happen should a pointer to a different type be used.

### Unsafe Use of Pipes in 2.6.x Kernel
Finally, the bug could also be the result of unsafe use of pipes and file descriptors in the context of a fork(), as seen in `init_cgi()`. Linux kernel version 2.6.x has known vulnerabilities related to pipes that can be used to gain privilege escalation. The excerpt of code below is from [this exploit](https://www.exploit-db.com/exploits/33322/); comparing the exploit source with the potentially vulnerable function in Boa, we can see very similar use of pipes in the context of a call to fork().

```c
    {
        pid = fork();
        if (pid == -1)
        {
            perror("fork");
            return (-1);
        }
        if (pid)
        {
            char path[1024];
            char c;
            /* I assume next opened fd will be 4 */
            sprintf(path, "/proc/%d/fd/4", pid);
                printf("Parent: %d\nChild: %d\n", parent_pid, pid); 
            while (!is_done(0))
            {
                fd[0] = open(path, O_RDWR);
                if (fd[0] != -1)
                {
                    close(fd[0]);
                }
            }
            //system("/bin/sh");
            execl("/bin/sh", "/bin/sh", "-i", NULL);
            return (0);
        }
```

From [Secure Coding, CERT](https://www.securecoding.cert.org/confluence/display/c/POS38-C.+Beware+of+race+conditions+when+using+fork+and+file+descriptors):
> When forking a child process, file descriptors are copied to the child process, which can result in concurrent operations on the file. Concurrent operations on the same file can cause data to be read or written in a nondeterministic order, creating race conditions and unpredictable behavior. 

## Conclusion
This was where my analysis ended. In addition to my limited knowledge of C and MIPS assembly, the difficulty in emulating the environment the binary typically runs in greatly reduced my ability to test my theories and come to a definitive conclusion. The following step will be to reverse engineer the patched version of Boa and identify the fix. 

### References
- [Mitre: CVE-2017-9675](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9675)
- [DIR-605L Firmware Downloads](http://support.dlink.com/productinfo.aspx?m=DIR-605L)
- [D-Link DIR-605L Security Advisory](ftp://ftp2.dlink.com/SECURITY_ADVISEMENTS/DIR-605L/REVB/DIR-605L_REVB_RELEASE_NOTES_v2.08UIBETAB01_EN.pdf)
- [Boa 0.94.14rc21 Source](http://www.boa.org/boa-0.94.14rc21.tar.gz)
- [Linux Kernel 2.6.x - 'pipe.c' Privilege Escalation](https://www.exploit-db.com/exploits/33322/)
- [POS38-C. Beware of race conditions when using fork and file descriptors](https://www.securecoding.cert.org/confluence/display/c/POS38-C.+Beware+of+race+conditions+when+using+fork+and+file+descriptors)