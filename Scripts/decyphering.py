#!/usr/bin/python
#This file has been made to comply 
#with the style of  cs7ns1/assignments/practical5/as5-makeinferno.py 
#In case of code reused from the script above, original comments were kept
#This code uncovers only 1 layer of the Inferno Ball
##Preliminary version, might have tons of bugs, watch out!


import os,sys,argparse,tempfile,shutil

# notes on secretsharing module below:
# - sudo -H pip install secret-sharing is needed first
# - secretsharing uses /dev/random by default, which is slow as it
#   gathers entropy from OS events - that's not only slow, but can
#   also frequently block, to get around this edit the source and
#   change it to use /dev/urandom which won't block
#   source to edit for me was:
#   /usr/local/lib/python2.7/dist-packages/secretsharing/entropy.py  
import secretsharing as sss

# for JSON output
import jsonpickle # install via  "$ sudo pip install -U jsonpickle"

# for hashing passwords
from hashlib import sha256

# needed for these: sudo -H pip install passlib argon2_cffi
from passlib.hash import pbkdf2_sha256,argon2,sha512_crypt,sha1_crypt

# for non-security sensitive random numbers
from random import randrange

# for encrypting you need: sudo -H pip install pycrypto
import base64
from Crypto.Cipher import AES
from Crypto import Random

#function from as5-makeinferno.py 
def pxor(pwd,share):
    '''
      XOR a hashed password into a Shamir-share

      1st few chars of share are index, then "-" then hexdigits
      we'll return the same index, then "-" then xor(hexdigits,sha256(pwd))
      we truncate the sha256(pwd) to if the hexdigits are shorter
      we left pad the sha256(pwd) with zeros if the hexdigits are longer
      we left pad the output with zeros to the full length we xor'd
    '''
    words=share.split("-")
    hexshare=words[1]
    slen=len(hexshare)
    hashpwd=sha256(pwd).hexdigest()
    hlen=len(hashpwd)
    outlen=0
    if slen<hlen:
        outlen=slen
        hashpwd=hashpwd[0:outlen]
    elif slen>hlen:
        outlen=slen
        hashpwd=hashpwd.zfill(outlen)
    else:
        outlen=hlen
    xorvalue=int(hexshare, 16) ^ int(hashpwd, 16) # convert to integers and xor 
    paddedresult='{:x}'.format(xorvalue)          # convert back to hex
    paddedresult=paddedresult.zfill(outlen)       # pad left
    result=words[0]+"-"+paddedresult              # put index back
    return result


#function from as5-makeinferno.py
def pwds_shares_to_secret(kpwds,kinds,diffs):
    '''
        take k passwords, indices of those, and the "public" shares and 
        recover shamir secret
    '''
    shares=[]
    for i in range(0,len(kpwds)):
        shares.append(pxor(kpwds[i],diffs[kinds[i]]))
    secret=sss.SecretSharer.recover_secret(shares)
    return secret

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s : s[:-ord(s[len(s)-1:])]

def decrypt(enc, key):
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:]))

def sortPasswords(passwords, origHashes):
	hashes = []
	solved = []

	for item in pots:
		hashpart, pwd = item.split(':')
		hashes.append(hashpart.strip())
		solved.append(pwd.strip())

	sortedhashes = []
	i=0
	for item in origHashes:
		if item in hashes:
			index = hashes.index(item)
			sortedhashes.append(solved[index].strip())
			i = i+1
		else:
			sortedhashes.append('\n')
	return sortedhashes, solved
#main code...

# magic JSON incantation (I forget why, might not even be needed here:-)
# above kept just in case
jsonpickle.set_encoder_options('json', sort_keys=True, indent=2)
jsonpickle.set_encoder_options('simplejson', sort_keys=True, indent=2)

#more magic JSON with no clear purpose
jsonpickle.set_decoder_options('json', sort_keys=True, indent=2)
jsonpickle.set_decoder_options('simplejson', sort_keys=True, indent=2) 


# usage
def usage():
    print >>sys.stderr, "Usage: " + sys.argv[0] + " -p <pwdfile> -s <shares> -l <layer> [-D <destdir>]" 
    sys.exit(1)

# getopt handling
argparser=argparse.ArgumentParser(description='Decypher one layer')
argparser.add_argument('-p','--potfile',     
                    	dest='potfile',
						help='potfile')
argparser.add_argument('-s','--shares',     
                    	dest='shares',
						help='file containing shares from inferno ball')
argparser.add_argument('-l','--layer',     
                    	dest='enclayer',
						help='file containing next encrypted layer from inferno ball')
argparser.add_argument('-hs','--hashes',     
                    	dest='ohashes',
						help='file containing all password hashes from inferno ball')
argparser.add_argument('-D','--destdir',     
                    	dest='destdir',
						help='directory for output file')
args=argparser.parse_args()

# post opt checks
if args.potfile is None:
	usage()
if args.shares is None:
	usage()
if args.enclayer is None:
	usage()
if args.ohashes is None:
	usage()

if not os.path.isfile(args.potfile) or not os.access(args.potfile,os.R_OK):
    print "Can't read " + args.potfile + " - exiting"
    sys.exit(2)

#getting lines from the potfile
pots=[]
with open(args.potfile,"r") as pwdf:
    for line in pwdf:
        pots.append(line.strip())

#getting hashes 
origHashes = []
with open(args.ohashes, 'r') as ohsh:
	for line in ohsh:
		origHashes.append(line.strip())

npasswords=len(pots)

cyphertext=[]
shares=[]
with open(args.shares, "r") as shf:
	for line in shf:
		shares.append(line.strip())

with open(args.enclayer, 'r') as encf:
	cyphertext = encf.read()

destdir="."
if args.destdir is not None:
	destdir=args.destdir

if not os.access(destdir,os.W_OK):
    # not checking we can write to destdir but feck it, good enough:-)
    print "Can't read " + destdir + " - exiting"
    sys.exit(3)

#sorting passwords according to their original order and getting raw passwords
sortedPwds, passwords =sortPasswords(pots, origHashes)

#getting the indexes of passwords solved
kinds = []
index = 0
for i in sortedPwds:	
	if i != '\n':
		kinds.append(index)
	index = index +1

levelsecret= pwds_shares_to_secret(passwords, kinds, shares)

text = decrypt(cyphertext, levelsecret.zfill(32).decode('hex'))

with open('nextLayer.as5', 'w') as nL:
	nL.write(text)


