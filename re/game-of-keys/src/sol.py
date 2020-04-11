import base64
from itertools import cycle, product, combinations
import random



class myGame():

    def __init__(self, xdim=4, ydim=4):
        self.x=xdim
        self.y=ydim
        self.matrix = []
        for i in range(self.x):
            row = []
            for j in range(self.y):
                row.append(0)
            self.matrix.append(row)
        
        words=[]
        with open('wordlist.txt') as f:
            for line in f:
                words.append(line.strip())
            for i in range(self.x):
                
                for j in range(self.y):
                     self.matrix[j][i]=words[i+j]


    def make_keys(self, *args, **kwargs):



      
        # pick a key:
        keyArray=[]
        
        keyArray.append(self.matrix[args[0]][args[1]])
        keyArray.append(self.matrix[args[2]][args[3]])

        
        key=''
        for k in keyArray:
            key=key.strip()+str(k).strip()

        return key


    def checkdata(self, key):
        f=base64.b64decode(b'NSYDUhoVWQ8SQVcOAAYRFQkORA4FQVMDQQ5fQhUEWUYMDl4MHA==')
        data=f.decode('ascii')

        c = ''.join(chr(ord(c)^ord(k)) for c,k in zip(data, cycle(key)))
        if c.__contains__('TG20{this'):
            print('%s ^ %s = %s' % (data, key, c))
        


if __name__ == "__main__":
    mgame=myGame(25, 25)
  
    keys=[]
    for i in range(30000):
        keys.append(mgame.make_keys(random.randint(0,24), random.randint(0,24), random.randint(0,24), random.randint(0,24)))
        
    print(len(keys))

    for key in keys:
        mgame.checkdata(key)

    
    

 
       