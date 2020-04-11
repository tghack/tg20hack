import sys
import xml.sax

class DummyHandler(xml.sax.ContentHandler):
    def __init__(self):
        self.curpath = []

    def characters(self, data):
        print(data)


def main():
    sys.stdout.write("Welcome to this absolutely not suspicious XML element extractor!\n\n")
    sys.stdout.flush
    while True:
        sys.stdout.write("\nPlease enter your XML here:\n")
        sys.stdout.flush

        try:
            textIn = input("")

            file = open("tmp.xml", "w+")
            file.write(textIn)
            file.close()

            parser = xml.sax.make_parser()
            parser.setContentHandler(DummyHandler())
            parser.setFeature(xml.sax.handler.feature_external_ges, True)
            parser.parse("tmp.xml")
        except:
            sys.stdout.write("Oh no, something bad happened! Please try again.\n")
            sys.stdout.flush


if (__name__ == "__main__"):
    main()


