***

### Introduction to web attacks

-  HTTP Verb Tampering: Sending malicious requests using unexpected methods
- Insecure Direct Object Reference (IDOR): Accessing resources that should only be accessed by the owner of that resources or an authorized user.
- XML External Entity (XXE) Injection: Sending malicious XML requests. Which are parsed by the application that is using outdated XML libraries.

### Intro to HTTP Verb Tampering

- [9 http verbs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods)
- **Insecure configuration** may allow unauthenticated users to send certain HTTP methods that should actually require authentication.
- **Insecure coding** when web devs applies specific filters to mitigate particular vulnerabilities while not covering all HTTP methods with that filter.

### Bypassing Basic Authentication

- We can check the URL's that require authentication and then intercept the request in burp and check what HTTP method is being used.
- In burp we can right click the request and change the method and try various methods and check the responses. 
- We can also check what methods the server accepts with the following:
```
curl -i -X OPTIONS http://SERVER_IP:PORT/
```
- We can try sending the other requests the server accepts like `HEAD` (This verb does not send a response)

### Bypassing Security Filters

- Another type of HTTP verb tampering vulnerability is caused by Insecure coding errors made during the development of the web application, which lead to web application not covering all HTTP methods. 
	- Eg. Commonly found in security filters that detect malicious requests. For example, if a security filter used to detect injection vulnerabilities and only checked for for injection in POST parameters (e.g. `$_POST['parameter'])` it may be possible to bypass it by simply changing the request method to `GET`)
	- We can test this by running basic linux commands and capturing the request in Burp and changing the request methods and observing the results.
	