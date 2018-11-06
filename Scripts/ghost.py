#!/usr/bin/python

# Copyright (C) 2018, Arun Thundyill Saseendran | ats0stv@gmail.com, thundyia@tcd.ie
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

"""     Script to decrypt the inferno ball
        Code inspired and adapted from the as5-makeinferno.py 
        in https://github.com/sftcd/cs7ns1/blob/master/assignments/practical5/as5-makeinferno.py
        RC: 0-Good 1-Generic Error 2-FNF
"""
import json
import base64
import logging
import jsonpickle
import secretsharing as sss
import os,sys,argparse,tempfile,shutil

from Crypto import Random
from hashlib import sha256
from random import randrange
from Crypto.Cipher import AES
from passlib.hash import pbkdf2_sha256,argon2,sha512_crypt,sha1_crypt

DEBUG = False
# Log Configuration
logging.basicConfig(level=logging.INFO)

SEPERATOR_STRING = '**** -=-=-=-=-=-=-=-==-=-=-= ****'

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

def pwds_shares_to_secret(kpwds,kinds,diffs):
    '''
        take k passwords, indices of those, and the "public" shares and 
        recover shamir secret
    '''
    shares=[]
    # print 'pwds = {}, kinds = {}, diffs = {}'.format(str(kpwds), str(kinds), str(diffs))
    previousSecret = ''
    for i in range(0,len(kpwds)):
        shares.append(pxor(kpwds[i],diffs[kinds[i]]))
        secret=sss.SecretSharer.recover_secret(shares)
        print secret + '\n' + previousSecret + '\n\n'
        if secret == previousSecret:
            print formatAsHeader(' :):) GOT THE SECRET :):) ')
            logging.info('Found reliable secret at k = {}'.format(str((i+1))))
            return secret
        previousSecret = secret
    logging.error('Could not find a reliable secret. Sending what I got')
    return secret

# modified from https://www.quickprogrammingtips.com/python/aes-256-encryption-and-decryption-in-python.html
BLOCK_SIZE = 16
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

def decrypt(enc, password):
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(password, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(enc[16:]))
    return bytes.decode(decrypted)

def init():
    # From Stephen's Code - As is - So I too don't know why. Was in a hurry to even try to learn!!
    # magic JSON incantation (I forget why, might not even be needed here:-)
    jsonpickle.set_encoder_options('json', sort_keys=True, indent=2)
    jsonpickle.set_encoder_options('simplejson', sort_keys=True, indent=2)


def emptyTheFile(filePath):
    if os.path.isfile(filePath):
        with open(filePath,'w') as file:
            file.write('')

def formatAsHeader(text):
    return '\n' + SEPERATOR_STRING + '\n' + text.center(len(SEPERATOR_STRING))+ '\n' + SEPERATOR_STRING + '\n\n'


def parseArguments():
    argparser=argparse.ArgumentParser(description='Recover the secret and decipher one level of interno ball')  
    argparser.add_argument('-p','--potFile',     
                    help='The path of the potfile',
                    required=True)
    argparser.add_argument('-i','--infernoBall',     
                    help='The path of the infernoBall that you are trying to crack',
                    required=True)
    argparser.add_argument('-s','--secretsFile',     
                    help='The path of the output secrets file',
                    required=True)
    argparser.add_argument('-o','--outputInferno',     
                    help='The path of the output inferno ball - the next level',
                    required=True)
    argparser.add_argument('-f','--flash',     
                    help='flash the existing secrets file and start afresh', action='store_true')
    argparser.add_argument('-d','--debug',     
                    help='flash the existing secrets file and start afresh', action='store_true')
    args=argparser.parse_args()
    return args

def postArgParseCheck(args):
    if not os.path.isfile(args.potFile) or not os.access(args.potFile,os.R_OK):
        logging.error('The potfile {} is not present or not readable'.format(args.potFile))
        sys.exit(2)
    if not os.path.isfile(args.infernoBall) or not os.access(args.infernoBall,os.R_OK):
        logging.error('The inferno ball file {} is not present or not readable'.format(args.infernoBall))
        sys.exit(2)
    if args.flash:
        emptyTheFile(args.secretsFile)
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
        global DEBUG
        DEBUG = True


def readAndCreateMapFromPot(inputFilePath):
    potMap = {}
    try:
        with open(inputFilePath, 'r') as file:
            for line in file:
                data = line.strip()
                if ':' in data:
                    lineSplit = data.split(':')
                    if len(lineSplit) == 2:
                        potMap[lineSplit[0]] = lineSplit[1]
                    elif len(lineSplit) > 2:
                        potMap[lineSplit[0]] = ':'.join(lineSplit[1:])
                    else:
                        logging.error('A non pot format line in the file. The line is {}'.format(line))
        return potMap
    except Exception as e:
        logging.error()
        logging.error(e)
        sys.exit(2)

def parseInfernoBall(inputFilePath):
    try:
        logging.info('Parsing the infernoBall')
        jsonData = None
        with open(inputFilePath, 'r') as file:
            jsonData = json.load(file)
        cipher = str(jsonData['ciphertext'])
        hashes = [str(x) for x in jsonData['hashes']]
        shares = [str(x) for x in jsonData['shares']]
        return cipher, hashes, shares
    except Exception as e:
        logging.error('Unable to parse the InfernoBall into ciphertext, hashes and shares')
        logging.error(e)
        sys.exit(1)


def decodeInferno(inferno):
    try:
        logging.info('Parsing the infernoBall')
        jsonData = json.loads(inferno)
        cipher = str(jsonData['ciphertext'])
        hashes = [str(x) for x in jsonData['hashes']]
        shares = [str(x) for x in jsonData['shares']]
        return cipher, hashes, shares
    except Exception as e:
        logging.error('Unable to parse the InfernoBall into ciphertext, hashes and shares')
        logging.error(e)
        sys.exit(1)

def extractKindAndPassword(hashes, potMap):
    logging.info('Count of hashes is {}'.format(str(len(potMap))))
    for k, v in potMap.items():
        if DEBUG:
            print k + ' ---- ' + v
    kindPwdMap = {}
    kind = []
    pwds = []
    count = 0
    for hashI in hashes:
        if hashI in potMap:
            if DEBUG:
                print 'Hash Match'
                print potMap[hashI]
            kindPwdMap[count] = potMap[hashI]
        count = count + 1
    for k, v in kindPwdMap.items():
        kind.append(k)
        pwds.append(v)
    return kind, pwds

def readSecrets(inputFilePath):
    secrets = []
    if os.path.isfile(inputFilePath):
        logging.info('Reading the contents of the secret file')
        with open(inputFilePath, 'r') as file:
            for line in file:
                secrets.append(str(line).strip())
    return secrets

def writeInfernoToFile(inferno, filename):
    emptyTheFile(filename)
    appendToFile(filename, inferno)

def appendToFile(outputFile, text):
    with open(outputFile, 'a') as outFile:
        outFile.write(text)

def writeLinesToFile(outputFile,lines):
    lines = [line+'\n' for line in lines]
    with open(outputFile,'a') as outFile:
        outFile.writelines(lines)

def writeSecretsToFile(secrets, filename):
    emptyTheFile(filename)
    writeLinesToFile(filename, secrets)

def validateInferno(inferno):
    try:
        jsonData = json.loads(inferno)
        return True
    except Exception as e:
        return False

def main():
    logging.info('Begin application')
    init()
    args = parseArguments()
    logging.info('Parsing Arguments')
    postArgParseCheck(args)
    logging.info('Parse arguments post check complete')
    potMap = readAndCreateMapFromPot(args.potFile)
    logging.info('Pot Map Created')
    cipherText, hashes, shares = parseInfernoBall(args.infernoBall)
    logging.info('Inferno ball JSON parsed')
    kind, pwds = extractKindAndPassword(hashes, potMap)
    logging.info('Getting the available passwords and its index')
    logging.info('Retrieving the level secret')
    levelSecret = pwds_shares_to_secret(pwds,kind, shares)
    logging.info('We have {} passwords out of {} hashes. k = {}'.format(str(len(pwds)), str(len(hashes)), str(len(pwds))))
    logging.info('Trying to decrypt using the level secret {}'.format(levelSecret))
    newSecret = [levelSecret]
    secrets = readSecrets(args.secretsFile)
    secrets = newSecret + secrets
    try:
        nextInferno = decrypt(cipherText,
                              levelSecret.zfill(32).decode('hex'))
        writeInfernoToFile(nextInferno, args.outputInferno)
        if validateInferno(nextInferno):
            print formatAsHeader(' :):) DECIPHERED :):) ')
            _, hashes, _ = decodeInferno(nextInferno)
            writeSecretsToFile(hashes, 'next.hashes')
            logging.info('Next level inferno retrieved. It can be found in {}'.format(args.outputInferno))
            writeSecretsToFile(list(set(secrets)), args.secretsFile)
            logging.info('The secrets file can be found in {}'.format(args.secretsFile))
        else:
            print formatAsHeader(' :(:( UNABLE TO DECIPHER :(:(')
            logging.error('JSON Validation of Inferno failed. Look in the path {} for output'.format(args.outputInferno))
    except Exception as e:
        if DEBUG:
            logging.exception('Unable to decipher')
        print formatAsHeader(' :(:( UNABLE TO DECIPHER :(:(')
    

if __name__ == '__main__':
  main()

