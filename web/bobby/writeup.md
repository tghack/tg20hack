# Writeup [Bobby](README.md)

## Challenge description
**Author: roypur**

**Difficulty: challenging**

**Category: web**

---

Little bobby forgot his password. Can you help him log in?

[bobby.tghack.no](https://bobby.tghack.no)

## Writeup

This is an SQL injection task.
If we try to enter `'` into all the fields, one at a time,
we get an error message when we try it on the "New password" field.

The error we get is

```
unrecognized token: "''' WHERE user=? AND pass=?"
```

Question marks are used in SQL to specify the location of data in prepared statements.
Since we get an error we can assume that something was injected into the query string 
before the prepared statement was made.

Since the "change password" page is something that updates information in the database
we can assume that it is using an SQL UPDATE statement.
With this assumption and the error message we got, we can guess that the statement being run is something like

```sql
UPDATE USERS SET pass='$pass' WHERE user=? AND pass=?
```

where `$pass` is what the user entered into the new password field.

From this we can create a payload that comments out the WHERE part
of the sql statement.

```sql
',user=?,pass=?;--
```

And the final SQL statement will look like this

```sql
UPDATE USERS SET pass='',user=?,pass=?;--' WHERE user=? AND pass=?
```

If we now enter the username and password we want to use into the
user and password field we have changed all the users in the database to have the username and password
you entered.

Logging in through the login page will get you the flag.

```
TG20{bobby_knows_his_sql}
```
