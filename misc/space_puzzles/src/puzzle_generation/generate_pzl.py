import argparse
import os

def generate_pzl(filename):
    print("Work work..")

    for name in filename:
        print("File... {}".format(name))
        os.system("./Nonograms/build/nonograms_solver -p {}".format(name))

    print("jobs' done!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Parse a .png file to a nonogram puzzle')
    parser.add_argument('filename', metavar='F', type=str, nargs='+',
        help='filename of file to parse')
    #parser.add_argument('--filename', metavar='F', type=str, nargs='+',
    #    default=["./images/black-white/*.png", "./images/color/*.png"], 
    #    help='filename of file to parse')

    args = parser.parse_args()

    generate_pzl(args.filename)

