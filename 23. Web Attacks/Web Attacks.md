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

### Verb Tampering Prevention

##### Insecure Configuration

- HTTP verb tampering can occur in most modern web servers.
- The vulnerability usually happens when we limit a page's authorization to a particular set of HTTP verbs/methods, which leaves the other remaining methods unprotected.
- Following is an example of vulnerable configuration for an Apache web server, which is located in the site configuration file (e.g. `000-default.conf`), or in a `.htaccess` web page configuration file:
```
<Directory "/var/www/html/admin">
    AuthType Basic
    AuthName "Admin Panel"
    AuthUserFile /etc/apache2/.htpasswd
	<Limit GET>
        Require valid-user
    </Limit>
</Directory>
```

- The above is setting the authorization configurations for the `admin` web directory. However, the `Required valid-user` setting will only apply to `GET` requests, leaving the page accessible through `POST, HEAD, OPTIONS`

- The following vulnerability shows the same vulnerability for a `Tomcat` web server configurations, which can be found in the `web.xml` file for a certain Java web application:
```
<security-constraint>
    <web-resource-collection>
        <url-pattern>/admin/*</url-pattern>
        <http-method>GET</http-method>
    </web-resource-collection>
    <auth-constraint>
        <role-name>admin</role-name>
    </auth-constraint>
</security-constraint>
```

- Follow is an example for an `ASP.NET` configurations found in the `web.config` file of a web application:
```
<system.web>
    <authorization>
        <allow verbs="GET" roles="admin">
            <deny verbs="GET" users="*">
        </deny>
        </allow>
    </authorization>
</system.web>
```

- It's not secure to limit the authorization configuration to a specific HTTP verb. This is why we should always avoid restricting authorization to a particular HTTP method and always allow/deny all HTTP verbs and methods.
- If we want to specify a single method, we can use safe keywords, like `LimitException` in Apache, `http-method-omission` in Tomcat, and `add/remove` is ASP.NET, which cover all verbs except the specified ones.
- To avoid similar attacks, we should generally consider `disabling/denying` all `HEAD` requests unless specifically required by the web applications.

##### Insecure Coding

```

if (isset($_REQUEST['filename'])) {
    if (!preg_match('/[^A-Za-z0-9. _-]/', $_POST['filename'])) {
        system("touch " . $_REQUEST['filename']);
    } else {
        echo "Malicious Request Denied!";
    }
}
```

- If we were only considering Command Injection vulnerabilities, we would say that this is securely coded.
- The `preg_match` function properly looks for unwanted special characters and does not allow the input to go into the command if any special characters are found. (In this case the fatal error is made due to inconsistent use of HTTP methods and not due to Command Injection)
- We see that the `preg_match` filter only checks for special characters in the `POST` parameters with `$POST['filename']`. 
	- The system command uses the `$REQUEST['filename']` variable, which covers both `GET` and `POST` parameters. This will lead to command injection if we use the `GET` method since it will not get stopped by `preg_match` function.
- To avoid HTTP verb Tampering vulnerabilities in our code, we must be consistent with our use of HTTP methods and ensure that the same method is always used for any specific functionality across the web application.
	- Its always advised to expand the scope of testing in security filters by testing all request parameters. This can be done with the following functions and variables:

|Language|Function|
|---|---|
|PHP|`$_REQUEST['param']`|
|Java|`request.getParameter('param')`|
|C#|`Request['param']`|

