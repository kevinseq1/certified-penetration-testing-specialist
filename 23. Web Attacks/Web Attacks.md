***

### Introduction to web attacks

-  HTTP Verb Tampering: Sending malicious requests using unexpected methods
- Insecure Direct Object Reference (IDOR): Accessing resources that should only be accessed by the owner of that resources or an authorized user.
- XML External Entity (XXE) Injection: Sending malicious XML requests. Which are parsed by the application that is using outdated XML libraries.

---
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

---

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

---

### Insecure Direct Object Reference

- Most common web vulnerabilities and can significantly impact the vulnerable web application. 
- It occurs when a web application exposes a direct reference to an object, like a file or a database resource, which the end-user can directly control to obtain access to other similar objects. 
	- Example: `download.php?file_id=123` if the web app does not have proper acl's in place we could potentially access `file_id=124`
- There are may ways of implementing a solid access control system for web applications, like having a Role-Based Access Control (RBAC) system. The IDOR vulnerability mainly exists due to the lack of an access control on the back-end.
- Some of the impact of IDOR vulnerabilities include accessing private files and resources of other users that should not be accessible to us, like personal files or credit card data.
- These vulnerabilities may also lead to the elevation of user privileges from a standard  user to an administrator user, with IDOR Insecure Function Calls. For Example, many web applications expose URL parameters or APIs for admin-only functions in the front-end code of the web application and disable these functions for non-admin users. If the backend did not explicitly deny non-admin users from calling these functions. In that case we may be able to perform unauthorized administrative operations.

##### Identifying IDOR's

- We should study the HTTP requests to look for URL parameters or API's with an object reference (e.g `?uid=1 or ?filename=file_1.pdf`) and try incrementing/decrementing the values. If we get a successful hit to files that are not our own it would indicate an IDOR vulnerability
- AJAX Calls: We may also be able to identify unused parameters or API's in the front-end code in the form of JavaScript AJAX calls. Some web apps developed in JS frameworks may insecurely place all function calls on the front-end and use the appropriate ones based on the user role.
	- If we did not have an admin account, only the user-level functions would be used, while the admin functions would be disabled. However, we may still be able to find the admin functions if we look into the front-end JS code and may be able to identify AJAX calls to specific end-points or API's that contain direct object references. If we identify direct object references in the JS code, we can test them for IDOR vulnerabilities (It's not unique to admin functions and we can also test backend code if we have access to it)

```
function changeUserPassword() {
    $.ajax({
        url:"change_password.php",
        type: "post",
        dataType: "json",
        data: {uid: user.uid, password: user.password, is_admin: is_admin},
        success:function(result){
            //
        }
    });
}
```

- We can also test for hashed and encoded object references (In some cases we may also have to manually identify the hashing algorithms).

```
$.ajax({
    url:"download.php",
    type: "post",
    dataType: "json",
    data: {filename: CryptoJS.MD5('file_1.pdf').toString()},
    success:function(result){
        //
    }
});
```

- In advanced IDOR attacks, we may need to register multiple users and compare their HTTP requests and object references. This may allow us to understand how the URL parameters and unique identifiers are being calculated and then calculate them for other users to gather their data.

```
{
  "attributes" : 
    {
      "type" : "salary",
      "url" : "/services/data/salaries/users/1"
    },
  "Id" : "1",
  "Name" : "User1"

}
```

- The second user may not have all the API parameters to replicate the call and should not be able to make the same call as `User1`. However, with these details at hand, we can try repeating the same API call while logged in as `User2` to see if the web application returns anything. Such cases may work if the web application only requires a valid logged-in session to make the API call but has no access control on the back-end to compare the caller's session with the data being called.

##### IDOR's Prevention

- Since they are mainly caused by improper access controls on the back-end servers. To prevent such vulnerabilities, we first have to build an object-level access control system and then use secure references for our objects when storing and calling them.
-  To avoid exploiting IDOR vulnerabilities, we must map the RBAC to all objects and resources. The back-end server can allow or deny every request, depending on whether the request's role has enough privileges to access the objects or the resource.

```
match /api/profile/{userId} {
    allow read, write: if user.isAuth == true
    && (user.uid == userId || user.roles == 'admin');
}
```

- Even after building a solid access control system, we should never use object references in clear text or simple patterns (e.g. `uid=1`). We should always use strong and unique references, like salted hashes or `UUID`'s. For example, we can use `UUID V4` to generate a strongly randomized id for any element, which looks something like (`89c9b29b-d19f-4515-b2dd-abb6e693eb20`). Then, we can map this `UUID` to the object it is referencing in the back-end database, and whenever this `UUID` is called, the back-end database would know which object to return. The following example PHP code shows us how this may work:

```
$uid = intval($_REQUEST['uid']);
$query = "SELECT url FROM documents where uid=" . $uid;
$result = mysqli_query($conn, $query);
$row = mysqli_fetch_array($result));
echo "<a href='" . $row['url'] . "' target='_blank'></a>";
```

- Strong object referencing is always the second step after implementing a strong access control system. Furthermore, some of the techniques would work even with unique references if the access control system is broken, like repeating one user's request with another user's session.

##### Mass IDOR Enumeration

- Insecure Parameters: Static file IDOR is when the parameter we are testing has a predictable pattern. For example: 
```
/documents/Invoice_1_09_2021.pdf
/documents/Report_1_10_2021.pdf
```

- The number `1` in the example above is the `uid` of a user. We could change the `uid` and check if we can get the information of another user.
- Mass Enumeration: For the example above we could use fuzzing(`Burp Intruder`or `ZAP Fuzzer`) to test the files for other users.
- For the file links we could also inspect the element in the browser.
```html
<li class='pure-tree_link'><a href='/documents/Invoice_3_06_2020.pdf' target='_blank'>Invoice</a></li>
<li class='pure-tree_link'><a href='/documents/Report_3_01_2020.pdf' target='_blank'>Report</a></li>
```
- We may `curl` the page and `grep` for this line `<li class='pure-tree_link'>`
```
curl -s "http://SERVER_IP:PORT/documents.php?uid=1" | grep "<li class='pure-tree_link'>"`


<li class='pure-tree_link'><a href='/documents/Invoice_3_06_2020.pdf' target='_blank'>Invoice</a></li>
<li class='pure-tree_link'><a href='/documents/Report_3_01_2020.pdf' target='_blank'>Report</a></li>
```

- We can use regex to just get the file patterns
```
curl -s "http://SERVER_IP:PORT/documents.php?uid=3" | grep -oP "\/documents.*?.pdf"

/documents/Invoice_3_06_2020.pdf
/documents/Report_3_01_2020.pdf
```

- We can use a bash script to loop over the `uid` parameter and return the document of all employees, and then use `wget` to download each document link:
```
#!/bin/bash

url="http://SERVER_IP:PORT"

for i in {1..10}; do
        for link in $(curl -s "$url/documents.php?uid=$i" | grep -oP "\/documents.*?.pdf"); do
                wget -q $url/$link
        done
done
```

