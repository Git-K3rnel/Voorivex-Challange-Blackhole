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







