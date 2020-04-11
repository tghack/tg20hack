#! /usr/bin/env python3
import string
import csv


def password_features(password):
    password = password.split("\n")[0]
    uppercase = sum(1 for c in password if c.isupper())
    lowercase = sum(1 for c in password if c.islower())
    numerics = sum(1 for c in password if c.isnumeric())
    specials = sum(1 for c in password if c in string.punctuation)
    lenght = len(password)
    return {"password_length": lenght, "uppercase_count": uppercase, "lowercase_count": lowercase, "numeric_count": numerics, "special_count": specials}


if __name__ == "__main__":
    passwords = open("./password.txt").readlines()
    with open("password.csv", mode="w") as f:
        fieldnames = ["password_length", "uppercase_count", "lowercase_count", "numeric_count", "special_count", "label"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for password in passwords:
            pass_features = password_features(password)
            pass_features["label"] = 0
            writer.writerow(pass_features)
