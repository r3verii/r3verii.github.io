---
layout: post
title: "Znuny OTRS CVEs : CVE-2024-32491, CVE-2024-32492, CVE-2024-32493"
date: 2025-04-08T08:14:54+00:00
img_dir: "/assets/2024-03-20-znuny-cves/images"
description: "In this post I detail two critical security flaws I discovered last year in the Znuny / OTRS ticket-ing system: a path-traversal file-upload bug that can be leveraged for remote code execution, and a time-based SQL injection in the draft-form cleanup routine. The write-up walks through root cause analysis, step-by-step PoCs, impact, official patches, and mitigation tips for administrators who are still running unpatched instances."
categories: [cve]
---

# CVE-2024-32491 |  File upload path traversal to RCE

**Overview**
- Date : 2024-04-17
- Affected : All versions of Znuny and Znuny LTS from 6.0.31 up to and including 6.5.7. All versions of Znuny from 7.0.1 up to and including 7.0.16.
- Severity : Critical
- CVE : CVE-2024-32491 
- Resources : [NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-32491) - [Znuny Advisory](https://www.znuny.org/en/advisories/zsa-2024-01)

**Premise** : In default installations (that use the DB module for cached file uploads), this vulnerability is not present. So to exploit this vulnerability , you need to set `Kernel::System::Web::UploadCache::FS`

![]({{ page.img_dir | relative_url }}/Easy_Mergers_v0.1/images/image.png)

The vulnerability is in the creation/editing form of a ticket, where an attachment can be uploaded.

A logged-in user can upload a file (via a manipulated AJAX Request) to an arbitrary writable location by traversing paths. Arbitrary code can be executed if this location is publicly available through the web server.

Let's take a look at the source code, `/Kernel/System/Web/UploadCache/FS.pm:144` [GitHub](https://github.com/znuny/Znuny/blob/7c1e60ccc737b046c1e96fe1b0554fcf1c68f6f7/Kernel/System/Web/UploadCache/FS.pm#L144)

```perl

sub FormIDAddFile {
    my ( $Self, %Param ) = @_;

    [...]

    # get main object
    my $MainObject = $Kernel::OM->Get('Kernel::System::Main');

    # files must readable for creator
    return if !$MainObject->FileWrite(
        Directory  => $Directory,
        Filename   => "$Param{Filename}", # <--- No sanitization or control on filename
        Content    => \$Param{Content},
        Mode       => 'binmode',
        Permission => '640',
        NoReplace  => 1,
    );

    [...]
}

```

As we see from the code, the `FormIDAddFile` function takes the filename from the HTTP request without any sanitization on the path

This is an example of a malicious request that allows the attacker to upload a file to any location on the system (as long as it has write permissions) , in this case I am uploading to the `../../../../../../../opt/znuny-7.0.15/var/httpd/htdocs/js/js-cache/<filename>` (Path traversal in the filename) which is an externally reachable static js file directory.

![]({{ page.img_dir | relative_url }}/Easy_Mergers_v0.1/images/image3.png)

![]({{ page.img_dir | relative_url }}/Easy_Mergers_v0.1/images/image4.png)

In this case I loaded a very simple webshell that allows me to run os commands on the host (RCE)

To mitigate this vuln just use the function basename() :

![]({{ page.img_dir | relative_url }}/Easy_Mergers_v0.1/images/image.jpg)

![]({{ page.img_dir | relative_url }}/Easy_Mergers_v0.1/images/image2.jpg)


---

# CVE-2024-32493 | Second Order SQL Injection

**Overview**
- Date : 2024-04-17
- Affected : All versions of Znuny LTS from 6.5.1 up to including 6.5.7. All versions of Znuny from 7.0.1 up to including 7.0.16.
- Severity : medium
- CVE : CVE-2024-32493 
- Resources : [NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-32493) - [Znuny Advisory](https://www.znuny.org/en/advisories/zsa-2024-03)


I found an SQLI vulnerability in the function  "FormIDCleanUp()" , in the file `/Znuny/Kernel/System/Web/UploadCache/DB.pm:310` [GitHub](https://github.com/znuny/Znuny/blob/7c1e60ccc737b046c1e96fe1b0554fcf1c68f6f7/Kernel/System/Web/UploadCache/DB.pm#L310) 

```perl

sub FormIDCleanUp {

    [...]
    
    my $SQL = 'DELETE FROM web_upload_cache
            WHERE create_time_unix < ?';


    if (@DraftForms) {
        my @SeparatedDraftForms = map {"'$_'"} @DraftForms;
        $SQL .= ' AND form_id NOT IN (' . join( ',', @SeparatedDraftForms ) . ')'; # concatenates user input @SeparatedDraftForms into sql query without prepared statement or sanitization
    }

    return if !$Kernel::OM->Get('Kernel::System::DB')->Do(
        SQL  => $SQL,
        Bind => [ \$CurrentTile ],
    );

    return 1;
}


```

The `FormIDCleanUp()` function is triggered by a cronjob every hour (for testing purposes I reduced the time to 1 minute) and deletes all cached ticket attachment files with a timestamp older than 24h , excluding files in draft forms , so it is possible to inject a malicious query into the `FormID` of the draft forms

![]({{ page.img_dir | relative_url }}/Easy_Mergers_v0.1/images/image6.png)

![]({{ page.img_dir | relative_url }}/Easy_Mergers_v0.1/images/image7.png)

with this example query the malicious FormID will be saved and when the cronjob will trigger the function `FormIDCleanUp()` the where condition will always be true and it will delete all cached files including those with date less than 24h ago and those present in all draft forms.

So this is an SQLI of the “Second Order” or “Stored” type. [PortSwigger](https://portswigger.net/web-security/sql-injection#:~:text=Second%2Dorder%20SQL%20injection%20occurs,where%20the%20data%20is%20stored.) : 
```
First-order SQL injection occurs when the application processes user input from an HTTP request and incorporates the input into a SQL query in an unsafe way.

Second-order SQL injection occurs when the application takes user input from an HTTP request and stores it for future use. This is usually done by placing the input into a database, but no vulnerability occurs at the point where the data is stored. Later, when handling a different HTTP request, the application retrieves the stored data and incorporates it into a SQL query in an unsafe way. For this reason, second-order SQL injection is also known as stored SQL injection.
```

Below is an example of what the SQL variable contains , I modified the source code a bit by inserting some debug logs to follow the flow and read the contents of the variables :


![]({{ page.img_dir | relative_url }}/Easy_Mergers_v0.1/images/image8.png)

The complexity of the exploit reduces the criticality of vuln.
In the above example case I simply used a payload that makes DELETE always TRUE and deletes files but could turn into a data exfiltration.


# CVE-2024-32492  | Stored XSS 

**Overview**
- Date : 2024-04-17
- Affected : All versions of Znuny from 7.0.1 up to including 7.0.16.
- Severity : medium
- CVE : CVE-2024-32492 
- Resources : [NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-32492) - [Znuny Advisory](https://www.znuny.org/en/advisories/zsa-2024-02)


The ticket detail view on the customer front allows the execution of external JavaScript.

![]({{ page.img_dir | relative_url }}/Easy_Mergers_v0.1/images/image9.png)

![]({{ page.img_dir | relative_url }}/Easy_Mergers_v0.1/images/image10.png)