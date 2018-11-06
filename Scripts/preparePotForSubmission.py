#!/usr/bin/env python

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

"""     Script to convert a set of pot files into a 
        submittable format with .hashes extension
        Scalable Computing
"""
__author__ = "Arun Thundyill Saseendran"
__version__ = "0.0.1"
__maintainer__ = "Arun Thundyill Saseendran"
__email__ = "thundyia@tcd.ie"


import os
import re
import argparse


CONFIG_SORT_PWD_BY_LENGTH = True

ROOT = './'
OUTPUT_FILE = 'thundyia.broken'
COMBINED_POT_FILE = 'thundyia.pot'
UNIQUE_PASSWORD_LIST = 'thundyia.password'
INPUT_DIR = None
DESCRYPT_FILE_IDENTIFIER = 'descrypt' # Just for getting submitty to accept the use
PASSWORD_TYPE_DICT = {'num':[],'lower':[],'upper':[],'alnum':[],'other':[]}
REGEX_LOWER = '^[a-z]+$'
REGEX_UPPER = '^[A-Z]+$'
SEPERATOR_STRING = '**** -=-=-=-=-=-=-=-==-=-=-= ****'
PASSWORD_STATS_DICT = {'num':{'count':0,'percent':0,'minimum_length':100, 'maximum_length':0},
                       'lower':{'count':0,'percent':0,'minimum_length':100, 'maximum_length':0},
                       'upper':{'count':0,'percent':0,'minimum_length':100, 'maximum_length':0},
                       'alnum':{'count':0,'percent':0,'minimum_length':100, 'maximum_length':0},
                       'other':{'count':0,'percent':0,'minimum_length':100, 'maximum_length':0}}
TOTAL_PASSWORD_COUNT = 0
PASSOWRD_LENGTH_DICT = {}
CHAR_FREQ = {}
BROKEN_LIST = []
POT_LIST = []
formatDictOrig = {"wierdhash":[],"descrypt":[]}
formatDictNew = {"wierdhash":[],"descrypt":[]}


def formatOutputFileNames(outputFile):
    if '/' in outputFile:
        firstSplit = outputFile.split('/')
        if '.' in outputFile:
            outputFileSplit = firstSplit[-1].split('.')
            return str(outputFileSplit[0])+'.broken', str(outputFileSplit[0])+'.pot', str(outputFileSplit[0])+'.password'
    else:
        if '.' in outputFile:
            outputFileSplit = outputFile.split('.')
            return str(outputFileSplit[0])+'.broken', str(outputFileSplit[0])+'.pot', str(outputFileSplit[0])+'.password'


def emptyTheFile(filePath):
    if os.path.isfile(filePath):
        with open(filePath,'w') as file:
            file.write('')


def formatAsHeader(text):
    return '\n' + SEPERATOR_STRING + '\n' + text.center(len(SEPERATOR_STRING))+ '\n' + SEPERATOR_STRING + '\n\n'


def initializeOutputFiles():
    emptyTheFile(OUTPUT_FILE)
    emptyTheFile(COMBINED_POT_FILE)
    emptyTheFile(UNIQUE_PASSWORD_LIST)


def processArgs():
    global OUTPUT_FILE
    global INPUT_DIR
    global COMBINED_POT_FILE
    global UNIQUE_PASSWORD_LIST
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", "-d", help="The directory containing the pot files to be merged", required=True)
    parser.add_argument("--outputFile", "-o", help="The path of the output file. If not specified file called (Should not be a hidden file) "
	   +OUTPUT_FILE+ "in CWD will be created", required=False)
    args = parser.parse_args()
    INPUT_DIR = args.dir
    if args.outputFile:
        OUTPUT_FILE, COMBINED_POT_FILE, UNIQUE_PASSWORD_LIST = formatOutputFileNames(args.outputFile)


def segregatePasswordType(password):
    global PASSWORD_TYPE_DICT
    global TOTAL_PASSWORD_COUNT
    global PASSWORD_STATS_DICT
    global PASSOWRD_LENGTH_DICT
    TOTAL_PASSWORD_COUNT = TOTAL_PASSWORD_COUNT + 1
    passwordLength = len(password.strip())
    # print 'Got length of {}'.format(password)
    if passwordLength in PASSOWRD_LENGTH_DICT:
        PASSOWRD_LENGTH_DICT[passwordLength] = PASSOWRD_LENGTH_DICT[passwordLength] + 1
    else:
        PASSOWRD_LENGTH_DICT[passwordLength] = 1
    # print 'Char Length stats complete for {}'.format(password)
    try:
        if unicode(password.strip()).isnumeric():
            # print 'Inside num for {}'.format(password)
            PASSWORD_TYPE_DICT['num'].append(password)
            updatePasswordStats('num',passwordLength)
        elif re.match(REGEX_LOWER, password.strip()):
            # print 'Inside lower for {}'.format(password)
            PASSWORD_TYPE_DICT['lower'].append(password)
            updatePasswordStats('lower',passwordLength)
        elif re.match(REGEX_UPPER, password.strip()):
            # print 'Inside upper for {}'.format(password)
            PASSWORD_TYPE_DICT['upper'].append(password)
            updatePasswordStats('upper',passwordLength)
        elif unicode(password.strip()).isalnum():
            # print 'Inside alnum for {}'.format(password)
            PASSWORD_TYPE_DICT['alnum'].append(password)
            updatePasswordStats('alnum',passwordLength)
        else:
            # print 'Inside other for {}'.format(password)
            PASSWORD_TYPE_DICT['other'].append(password)
            updatePasswordStats('other',passwordLength)
    except Exception as e:
        print e
        print 'Unable to parse the password {}'.format(password)

def updatePasswordStats(passwordType,passwordLength):
    PASSWORD_STATS_DICT[passwordType]['count'] = PASSWORD_STATS_DICT[passwordType]['count'] + 1
    if passwordLength < PASSWORD_STATS_DICT[passwordType]['minimum_length']:
            PASSWORD_STATS_DICT[passwordType]['minimum_length'] = passwordLength
    if passwordLength > PASSWORD_STATS_DICT[passwordType]['maximum_length']:
            PASSWORD_STATS_DICT[passwordType]['maximum_length'] = passwordLength
        
def computerPasswordTypePercentage():
    global PASSWORD_STATS_DICT
    for key, value in PASSWORD_STATS_DICT.items():
        percent = float(PASSWORD_STATS_DICT[key]['count']) / TOTAL_PASSWORD_COUNT * 100;
        PASSWORD_STATS_DICT[key]['percent'] = percent

def prepareOutputFromFile(inputFile,outputFile):
    print 'Preparing outputfile from file {}'.format(inputFile)
    global BROKEN_LIST
    global POT_LIST
    addedLines = []
    passwords = []
    with open(inputFile,'r') as inFile:
        for line in inFile:
            if re.match('^sha256.*',line): # Convert back formatted pbkdf2 back to original
                splits = line.split(':')
                splits[0] = '$pbkdf2-'+splits[0]
                firstJoin = '$'.join(splits[:(len(splits)-1)])
                line = firstJoin +':'+ splits[-1]
            if ':' in line:
                splittedLine = line.split(':')
                if not re.match('^\$.*',line): # To handle the submitty issue
                    splittedLine[1] = splittedLine[1][:7].strip()
                    formattedLine = ' '.join(splittedLine)+'\n'
                else:
                    formattedLine = ' '.join(splittedLine)# Handling the windows \r\n issue
                line = line.replace('\r\n','\n')
                POT_LIST.append(line)
                BROKEN_LIST.append(str(formattedLine).strip()+'\n')
            else:
                print "The line '"+ line + "' in file "+ inputFile + " is not in pot format"


def writePasswordsByTypeToFile():
    appendToFile(UNIQUE_PASSWORD_LIST,formatAsHeader('Stats'))
    writeStatsToFile()
    for dictkey, value in PASSWORD_TYPE_DICT.items():
        appendToFile(UNIQUE_PASSWORD_LIST,formatAsHeader(dictkey))
        if CONFIG_SORT_PWD_BY_LENGTH:
            writeLinesToFile(UNIQUE_PASSWORD_LIST,list(sorted(set(value),key=len)))
        else:
            writeLinesToFile(UNIQUE_PASSWORD_LIST,list(sorted(set(value))))

def getPercentage(total,value):
    percent = round((float(value)/total*100),2)
    return str(value)+ " / {} ({}%)".format(str(total),str(percent))

def calulateCharacterDensity(formatDict):
    total = 0
    uniqchars = ''
    for key,value in formatDictNew.items():
        for passwd in value:
            data = passwd.strip()
            data = data.split(' ')
            data = data[1]
            total = total + len(data)
            for i in range(0,len(data)-1):
                if data[i] in CHAR_FREQ:
                    CHAR_FREQ[data[i]] = CHAR_FREQ[data[i]] + 1
                else:
                    CHAR_FREQ[data[i]] = 1
    appendToFile(UNIQUE_PASSWORD_LIST,formatAsHeader('Character Frequency'))
    for key, value in sorted(CHAR_FREQ.iteritems(), key=lambda (k,v): (v,k),reverse=True):
        uniqchars = uniqchars + key
        appendToFile(UNIQUE_PASSWORD_LIST,"\n{} -- ".format(key)+getPercentage(total,value))
    appendToFile(UNIQUE_PASSWORD_LIST,"\n\nUnique CharacterSet -- {}".format(uniqchars))
    appendToFile(UNIQUE_PASSWORD_LIST,"\n\nUnique CharacterSet Length -- {}".format(len(uniqchars)))


def writeStatsToFile():
    for line in list(set(BROKEN_LIST)):
        if re.match('^\$.*',line):
            splittedLine = line.split('$')
            if len(splittedLine) > 1:
                if splittedLine[1] in formatDictNew:
                    formatDictNew[splittedLine[1]].append(line)
                else:
                    formatDictNew[splittedLine[1]] = [line]
            else:
                formatDictNew["wierdHash"].append(line)
        else:
            formatDictNew["descrypt"].append(line)
    try:
        calulateCharacterDensity(formatDictNew)
    except Exception as e:
        print e.message
    appendToFile(UNIQUE_PASSWORD_LIST,formatAsHeader('Completed by Type'))
    total = 0
    for key,value in formatDictNew.items():
        total = total + len(value)
    for key,value in formatDictNew.items():
        for password in value:
            segregatePasswordType(password.split(' ')[1])
        if key == 'descrypt':
            appendToFile(UNIQUE_PASSWORD_LIST,"\ndescrypt -- "+getPercentage(total,len(value)))
        elif key == '1':
            appendToFile(UNIQUE_PASSWORD_LIST,"\nMD5 -- "+getPercentage(total,len(value)))
        elif key == '5':
            appendToFile(UNIQUE_PASSWORD_LIST,"\nSHA256 -- "+getPercentage(total,len(value)))
        elif key == '6':
            appendToFile(UNIQUE_PASSWORD_LIST,"\nSHA512 -- "+getPercentage(total,len(value)))
        elif key == 'pbkdf2-sha256':
            appendToFile(UNIQUE_PASSWORD_LIST,"\npbkdf2-sha256 -- "+getPercentage(total,len(value)))
        elif key == 'argon2i':
            appendToFile(UNIQUE_PASSWORD_LIST,"\nargon2i -- "+getPercentage(total,len(value)))
        else:
            appendToFile(UNIQUE_PASSWORD_LIST,"\n"+key+" -- "+getPercentage(total,len(value)))
    appendToFile(UNIQUE_PASSWORD_LIST,"\n** Total ** "+" -- "+str(total))

    appendToFile(UNIQUE_PASSWORD_LIST,formatAsHeader('Char Count Stats'))
    total = 0


    for key, value in PASSOWRD_LENGTH_DICT.items():
        total = total + value
    appendToFile(UNIQUE_PASSWORD_LIST,"\nTotal -- "+str(total))
    for key, value in sorted(PASSOWRD_LENGTH_DICT.iteritems(), key=lambda (k,v): (v,k),reverse=True):
        appendToFile(UNIQUE_PASSWORD_LIST,"\n"+str(key)+" chars -- "+str(value)+" ({})".format(str(round(float(value)/total*100,2))))
    appendToFile(UNIQUE_PASSWORD_LIST,formatAsHeader('Other Stats'))
    computerPasswordTypePercentage()
    for key, value in PASSWORD_STATS_DICT.items():
        appendToFile(UNIQUE_PASSWORD_LIST,"\n-- "+key)
        for k, v in value.items():
            appendToFile(UNIQUE_PASSWORD_LIST, "\n"+k+": "+str(v))
        appendToFile(UNIQUE_PASSWORD_LIST, "\n")
    appendToFile(UNIQUE_PASSWORD_LIST, "\n")

def writeLinesToFile(outputFile,lines):
    with open(outputFile,'a') as outFile:
        outFile.writelines(lines)


def appendToFile(outputFile, text):
    with open(outputFile, 'a') as outFile:
        outFile.write(text)

def createPasswordWordList(brokenList):
    file = './password.words'
    file2 = './password4.words'
    words = []
    wordd4 = []
    emptyTheFile(file)
    emptyTheFile(file2)
    for line in brokenList:
        brokenSplit = line.split(' ')
        words.append(brokenSplit[1])
        try:
            if len(brokenSplit[1].strip()) == 4:
                wordd4.append(brokenSplit[1])
            if len(brokenSplit[1].strip()) == 8:
                wordd4.append(brokenSplit[1].strip()[:4]+'\n')
                wordd4.append(brokenSplit[1].strip()[4:]+'\n')
        except Exception as e:
            print(e)
    writeLinesToFile(file,list(set(words)))
    writeLinesToFile(file2,list(set(wordd4)))



def processInput():
    try:
        for root, _, files in os.walk(INPUT_DIR):
            ROOT = root
            for file in files:
                if ".pot" in file:
                    filePath = os.path.join(root,file)
                    prepareOutputFromFile(filePath, OUTPUT_FILE)
        writePasswordsByTypeToFile()
        writeLinesToFile(OUTPUT_FILE,list(set(BROKEN_LIST)))
        print 'Password count {}'.format(str(len(set(BROKEN_LIST))))
        writeLinesToFile(COMBINED_POT_FILE,list(sorted(set(POT_LIST))))

    except Exception as e:
        print e.message


def displaySuccessMessage():
    print 'The output file can be found in {}'.format(OUTPUT_FILE)
    print 'The combined pot file can be found in {}'.format(COMBINED_POT_FILE)
    print 'The unique passwords file can be found in {}'.format(UNIQUE_PASSWORD_LIST)


def main():
    processArgs()
    initializeOutputFiles()
    processInput()
    createPasswordWordList(BROKEN_LIST)
    displaySuccessMessage()

main()







