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
- We can try send the other requests the server accepts like `HEAD` (This verb does not send a response)