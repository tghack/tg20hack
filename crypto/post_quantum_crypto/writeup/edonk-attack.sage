# coding: utf-8
# Sage code
# Author: Matthieu Lequesne
# Attack on EdonK scheme
# Designed to attack edonk128ref
# The KAT file PQCkemKAT.rsp of edonk128ref should placed be in the same directory.
# The function run_attack(i) runs the attack on the ith example of the KAT file.
# Source: https://groups.google.com/a/list.nist.gov/forum/#!topic/pqc-forum/sQuZCcHL1bU

import sys
import hashlib

m=128
L=6
nu=8
N=144
R=40
K=16

F=GF(2)
Fm.<x>=GF(2^m)
VFm = Fm.vector_space()
VFmN = VectorSpace(Fm,N)

## Main conversions

###  Str -> Bin -> Fm 

def str_to_bin(s): 
    bins=[]
    for i in range(len(s)//2):
        t = bin(int(s[2*i:2*i+2],16))[2:]
        while len(t)<8:
            t='0'+t
        for i in range(8):
            if t[7-i]=='0':
                bins.append(0)
            else:
                bins.append(1)
    return bins


def str_to_Fm(s):
    return Fm(list(str_to_bin(s)))


### Fm -> Bin -> Str -> Bytes

def bin_to_str(a):
    s=''
    for i in range(len(a)//8):
        t1=ZZ(0)
        t1=(ZZ(a[8*i])+2*ZZ(a[8*i+1])+4*ZZ(a[8*i+2])+8*ZZ(a[8*i+3]))
        t2=ZZ(0)
        t2=(ZZ(a[8*i+4])+2*ZZ(a[8*i+5])+4*ZZ(a[8*i+6])+8*ZZ(a[8*i+7]))
        s=s+str(hex(int(t2)))[2:]+str(hex(int(t1)))[2:]
    return s.upper()

def Fm_to_bytes(x):
    return bytearray.fromhex(bin_to_str(list(VFm(x))))


### Phi : F_{2^m} -> F_2^m

def phi(x): # Conversion F_{2^m} -> F_2^m
    return vector(F,m,VFm(x))

def phi_inv(v): # Conversion F_2^m -> F_{2^m}
    return Fm(list(v))

def phi_vect(x,L): # Conversion F_{2^m}^L -> F_2^{L*m}
    return vector(F,L*m,flatten([list(phi(x[i])) for i in range(L)]))

def phi_vect_inv(v,L): # Conversion F_2^{L*m} -> F_{2^m}^L
    return vector(Fm,L,list([v[m*i:m*(i+1)] for i in range(L)]))


## Parsing KAT

def parse(count=0):
    EdonK_input = open('PQCkemKAT.rsp', 'r')
    EdonK_input.readline()
    for i in range(7*count): # Go to count=count
        EdonK_input.readline()
    for i in range(3): # Skip line + count + seed
        EdonK_input.readline()
    pk = EdonK_input.readline()[5:-1] # Read public key
    EdonK_input.readline() # Skip secret key
    ct = EdonK_input.readline()[5:-1] # Read public key
    ss = EdonK_input.readline()[5:-1] # Read secret (only to assert that the attack is successful)
    EdonK_input.close()
    return(pk,ct,ss)


## Build Fm elements from strings

def get_pk(str_pk):
    def str_Gpubbase(i):
        return str_pk[i*32:(i+1)*32]
    def str_Gcoset(i):
        return str_pk[512+2*i:512+2*i+2]
    def str_Gcoeff(i,j):
        return str_pk[544+2*144*i+2*j:544+2*144*i+2*j+2]
    def hex_to_bin(s):
        bs = bin(int(s,16))[2:]
        while len(bs)<8:
            bs='0'+bs
        return bs
    def Gvec(i,j):
        dij = hex_to_bin(str_Gcoeff(i,j))
        cij = hex_to_bin(str_Gcoset(i))
        v = [0]*(2*nu)
        for k in range(nu):
            v[k] = F(0) if dij[nu-1-k]=='0' else F(1)
            v[k+nu] = F(0) if dij[nu-1-k]=='0' else F(1)
        for k in range(nu):
            if cij[nu-1-k]=='1':
                v[k]=v[k]+F(1)
        vt = vector(F,2*nu,v)
        return vt
    tGpubbase = []
    Gpubbase = vector(Fm,2*nu,[str_to_Fm(str_Gpubbase(i)) for i in range(2*nu)])
    Gpub = matrix(Fm,K,N,list([Fm(Gpubbase * Gvec(i,j)) for i in range(K) for j in range(N)]))
    alpha = Gpubbase[0] / Gpubbase[nu]
    return (Gpub,alpha)

def get_ct(str_ct):
    tciphertext = []
    for i in range(N):
        tciphertext.append(str_to_Fm(str_ct[i*32:(i+1)*32]))
    ciphertext = vector(Fm,N,tciphertext)
    str_h=str_ct[-64:]
    return (ciphertext, str_h)


## Hash

def hash_next(byt_e0,byt_e1):
    hash_next = hashlib.sha256()
    hash_next.update(byt_e0)
    hash_next.update(byt_e1)
    hex_e2e3 = hash_next.hexdigest()
    hex_e2 = hex_e2e3[:len(hex_e2e3)//2]
    hex_e3 = hex_e2e3[len(hex_e2e3)//2:]
    return bytearray.fromhex(hex_e2),bytearray.fromhex(hex_e3)

def hash_h(byt_s0,byt_s1,hex_sha2ofC):
    hash_h = hashlib.sha256()
    hash_h.update(byt_s1)
    hash_h.update(byt_s0)
    hash_h.update(bytearray.fromhex(hex_sha2ofC))
    hex_h = hash_h.hexdigest().upper()
    return hex_h

def hash_secret(byt_s0,byt_s1,hex_sha2ofC):
    hash_secret = hashlib.sha256()
    hash_secret.update(byt_s0)
    hash_secret.update(byt_s1)
    hash_secret.update(bytearray.fromhex(hex_sha2ofC))
    hex_secret = hash_secret.hexdigest().upper()
    return hex_secret

def hash_ciphertext(ciphertext):
    byt_ciphertext = []
    for i in range(N):
        byt_ciphertext.append(Fm_to_bytes(ciphertext[i]))
    hash_ciphertext = hashlib.sha256()
    for i in range(len(byt_ciphertext)):
        hash_ciphertext.update(byt_ciphertext[i])
    return hash_ciphertext.hexdigest()


## Reconstruct H''

def getGpub_bin(Gpub):
    Gpub_bin_t = []
    for i in range(N):
        for k in range(128):
            Gpub_bin_row = []
            for j in range(K):
                Gpub_bin_row += list(VFm(Gpub[j][i]*Fm(x^k)))
            Gpub_bin_t.append(Gpub_bin_row)
    Gpub_bin = matrix(F,N*m,K*m,Gpub_bin_t).transpose()
    return Gpub_bin

def getT(alpha):
    T_t = []
    for i in range(N):
        T_t_line = []
        T_t_line += [0]*(i*m)
        T_t_line += list(VFm(Fm(1)))
        T_t_line += [0]*((N-i-1)*m)
        T_t.append(T_t_line)
        T_t_line = []
        T_t_line += [0]*(i*m)
        T_t_line += list(VFm(alpha))
        T_t_line += [0]*((N-i-1)*m)
        T_t.append(T_t_line)
    T = (matrix(F,2*N,m*N,T_t)).transpose()
    return T

def getH2(Gpub, alpha): 
    Gpub_bin = getGpub_bin(Gpub)
    T = getT(alpha)
    GT = Gpub_bin * T
    Ker_Gt_mat = GT.right_kernel_matrix()
    H2temp = matrix(Fm,79,N,[phi_vect_inv(Ker_Gt_mat[i]*T.transpose(),N) for i in range(79)])
    assert (Gpub * H2temp.transpose()).is_zero()
    for i in range(R):
        for j in range(N):
            assert H2temp[i][j] == alpha or H2temp[i][j] == 1 or H2temp[i][j] == alpha+1 or H2temp[i][j] == 0
    H2_t = []
    for i in range(79):
        if H2temp[i] not in VFmN.subspace_with_basis(H2_t):
            H2_t.append(H2temp[i])
    assert len(H2_t)==R
    H2 = matrix(Fm,R,N,H2_t)
    return H2


## The Attack

def decode(ciphertext, H2, alpha):
    s = ciphertext * H2.transpose()
    Vcand = VFm.subspace([s[i] for i in range(R)])
    return Vcand

def retrieve_secret(Vcand, ciphertext, str_h):
    hex_sha2ofC = hash_ciphertext(ciphertext)
    for i in range(Vcand.cardinality()):
        e4_t = Fm(list((Vcand.list())[i]))
        byt_ebase4_t = Fm_to_bytes(e4_t)
        for j in range(Vcand.cardinality()):
            e5_t = Fm(list((Vcand.list())[j]))
            byt_ebase5_t = Fm_to_bytes(e5_t)
            (byt_s0_t,byt_s1_t)=hash_next(byt_ebase4_t,byt_ebase5_t)
            h = hash_h(byt_s0_t,byt_s1_t,hex_sha2ofC)
            if h == str_h:
                return (hash_secret(byt_s0_t, byt_s1_t, hex_sha2ofC))
    return ""

def attack(str_pk, str_ct):
    (Gpub, alpha) = get_pk(str_pk)
    (ciphertext, str_h) = get_ct(str_ct)
    H2 = getH2(Gpub, alpha)
    Vcand = decode(ciphertext, H2, alpha)
    secret = retrieve_secret(Vcand, ciphertext, str_h)
    return secret

def run_attack(count=0): # run_attack(i) runs the attack on the ith example of the KAT file
    assert 0<=count<100
    (str_pk, str_ct, str_ss) = parse(count)
    secret = attack(str_pk, str_ct)
    print ("Recovered secret = " + secret)
    if secret == str_ss:
        print("ATTACK SUCCESSFUL")
    else:
        print("ATTACK FAILED")

# run_attack(i) runs the attack on the ith example of the KAT file
#run_attack(0)
#
def main():
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <pubkey_file> <cipher_file> <secret_output_file>")
        return -1

    with open(sys.argv[1]) as f:
        pk = f.read().strip()
    with open(sys.argv[2]) as f:
        ct = f.read().strip()

    print("Running attack")
    secret = attack(pk, ct)
    print("Recovered secret = " + secret)

    with open(sys.argv[3], "w+") as f:
        f.write(secret)

    print(f"Wrote secret to {sys.argv[3]}")


if __name__ == "__main__":
    main()
