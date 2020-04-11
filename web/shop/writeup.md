# Writeup Shop

## Challenge description
**Author: roypur**

**Difficulty: easy**

**Category: web**

---

We found the Mother cult merch store. In addition to selling clothing items they sell some secrets we need.
For the time being we haven't been able to secure the funds necessary to do so. Can you help us?

- [shop.tghack.no](https://shop.tghack.no)

---

## Writeup

The challenge description tells us that we need to get some information from a website.
The website consists of two pages, a bank page and a store page.

We can borrow money from the bank, and spend it in the store.
The item we need to get is called Flag, and costs 1337$.
If we try to borrow 1337$ in the bank we are told that you can't have more than 200$ in debt.

When we inspect the source code of the store page
we can see that every item has a price and an id, both of which are posted to the server when we buy something.

```bash
curl --data "sum=10&id=13" https://shop.tghack.no/056201ef01f2b1b6f92430e24c10247ce66a9174d67865c32292b7b2d3c20227/store
```

When trying to purchase the item by just reducing the price we get the error `Insufficient funds!`.


```bash
curl --data "sum=10&id=30" https://shop.tghack.no/056201ef01f2b1b6f92430e24c10247ce66a9174d67865c32292b7b2d3c20227/store
```

When we try the exact same thing with an item that doesn't exist, we are able to purchase it at the price we specified.
That indicates that the data isn't properly validated.


```bash
curl --data "sum=-2000&id=30" https://shop.tghack.no/056201ef01f2b1b6f92430e24c10247ce66a9174d67865c32292b7b2d3c20227/store
```

If we try to buy an item that doesn't exist, with a negative price, we can see that the account balance increases instead of decreases.
Now we have the suficcient funds required to buy the flag.

We get the flag from the website when we buy the flag item in the store.

```
TG20{I_just_want_to_buy_a_real_flag}
```
