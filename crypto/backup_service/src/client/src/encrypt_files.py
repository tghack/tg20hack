from subprocess import call
from os import listdir
from sys import argv
from random import shuffle, randrange
from time import sleep


def main():
    if len(argv) < 2:
        print(f"Usage: {argv[0]} <file_directory>")
    else:
        files = listdir(argv[1])
        shuffle(files)
        for f in files:
            sleep_time = randrange(60)
            print(f"Sleeping for {sleep_time} seconds")
            sleep(sleep_time)
            print(f"Storing file: {f}")
            call(["cargo", "run", "--release", "store",
                  "http://kakekassa:3000", f"{argv[1]}/{f}"])


if __name__ == "__main__":
    main()
