# for creating convert-command for combining sevreal unown images into one
text = input("What should be assembled?\n")

pngs = ""
for letter in text.lower():
    if letter == " ":
        letter = "\\" + letter
    pngs += "unowns/201unown_" + letter + ".png "

print(f"convert {pngs}+append unown.png")
