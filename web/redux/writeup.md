# Writeup Redux

## Challenge description
**Author: Norasaurus**

**Difficulty: easy**

**Category: web**

---

Here is your Gaia form to get your weekly plant rations. Complete the form and 
reap your reward!

[redux.tghack.no](https://redux.tghack.no)

---

## Writeup

The challenge name is "Redux". Redux is a popular JavaScript library used for 
state management.

But what exactly is state management? When you are creating large web-forms 
(where users have to write a bunch of info such as name, age, height etc...) 
you want to at some point post that information to a backend. You could post 
the information to the server after every letter the user writes, but this 
would create a large load!

Instead, you want to save the data in the client, and only post to the server 
when the user clicks "submit form" (or something similar). Sometimes you also 
want to store a bunch of information from a backend in your client. Redux is a 
way to save all this client information in one, manageable place.


To see the entire redux state of an application you can download a Chrome 
extension:
[Redux dev tools](https://chrome.google.com/webstore/detail/redux-devtools/lmhkpmbekcpmknklioeibfkpmmfibljd)

You can then open the extension and look at the "Diff" and "State" tabs as you 
click around in the form. When you press the "Get my ration"-button you will see 
the flag in the Redux state.
It is important to disable Redux dev tools in production, so that nobody can 
keep track of your entire application state!
