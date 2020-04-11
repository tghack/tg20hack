from itertools import cycle 
import base64
def xor(data, key):
    c = ''.join(chr(ord(c)^ord(k)) for c,k in zip(data, cycle(key)))
    print('%s ^ %s = %s' % (data, key, c))
    message = ''.join(chr(ord(c)^ord(k)) for c,k in zip(c, cycle(key)))
    print('%s ^ %s = %s' % (c, key, message))
    b64e=base64.b64encode(c.encode('ascii'))
    print(b64e)
    b64d=base64.b64decode(b64e)
    print(b64d.decode('ascii'))

xor("TG20{this flag should be on teh moon}", "aa1baa1f")
