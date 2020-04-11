#!/usr/bin/env python3
import random
import string

year = "2820"
captain = "Captain bolbz"
starpower = "4200000000^42"
cyber_weapon = "133700"

for i in range(100):
    if i == 85:
        print("const char *answer_year{} = \"{}\";".format(i, year))
        continue;

    tmp = "".join(random.choices(string.digits, k=4))
    print("const char *answer_year{} = \"{}\";".format(i, tmp))

captain_name_list = [ "mariti", "o_o", "Pe", "wZ", "kake", "kongen", "roy", "pur", "odin", "je", "daddy", "DJ", "Smoking", "Gun", "9", "co", "no", "hac", "aleks", "il", "z", "up", "bol", "zzy", "Cha", "bz", "kriste", "bo" ]

for i in range(100):
    if i == 42:
        print("const char *answer_captain{} = \"{}\";".format(i, captain))
        continue;

    tmp = "".join(random.choices(captain_name_list, k=2))
    print("const char *answer_captain{} = \"Captain {}\";".format(i, tmp))
    
for i in range(100):
    if i == 5:
        print("const char *answer_starpower{} = \"{}\";".format(i, starpower))
        continue;

    tmp = "".join(random.choices(string.digits, k=10))
    print("const char *answer_starpower{} = \"{}^42\";".format(i, tmp))

for i in range(100):
    if i == 34:
        print("const char *answer_cyber_weapon{} = \"{}\";".format(i, cyber_weapon))
        continue;

    tmp = "".join(random.choices(string.digits, k=6))
    print("const char *answer_cyber_weapon{} = \"{}\";".format(i, tmp))
