#!/usr/bin/env python
"""     Script to create word lists for combinator attack
"""
__author__ = "Arun Thundyill Saseendran"
__version__ = "0.0.1"
__maintainer__ = "Arun Thundyill Saseendran"
__email__ = "thundyia@tcd.ie"


import os
import re
import argparse

OUTPUT_FILE = './output.txt'
LETTER_COUNT = 0
MAX_LETTER_COUNT = 0
MODE = -1
MASTERFILE = './master.file'
TOTAL_PROCESSED = 0
REGEX_LOWER = '^[a-z]+$'

def processArgs():
    global LETTER_COUNT
    global MAX_LETTER_COUNT
    global OUTPUT_FILE
    global MASTERFILE
    global MODE
    parser = argparse.ArgumentParser()
    parser.add_argument("--masterFile", "-mf", help="The path of the file containing all the files. Default: ./master.file", required=True)
    parser.add_argument("--outputFile", "-o", help="The path of the output file. If not specified file called (Should not be a hidden file) "
       +OUTPUT_FILE+ "in CWD will be created", required=False)
    parser.add_argument("--minChars", "-min", help="Minimum number of letters. Eg. 4", required=True)
    parser.add_argument("--maxChars", "-max", help="Maximum number of letters. Eg. 4", required=True)
    parser.add_argument("--convert", "-c", help="1 - Lower; 2 - Upper; 3 - As is, 4 - Select lower, 5 - select alnum", required=True)
    args = parser.parse_args()
    MASTERFILE = args.masterFile
    if args.outputFile:
        OUTPUT_FILE = args.outputFile
    try:
        LETTER_COUNT = int(args.minChars)
        MAX_LETTER_COUNT = int(args.maxChars)
    except Exception as e:
        print 'Unable to parse the number of characters'
        exit(1)
    try:
        MODE = int(args.convert)
        if not (MODE > 0 and MODE <= 5):
            print 'Mode should be within 1 and 5'
            exit(2)
    except Exception as e:
        print 'Unable to parse the mode'
        exit(1)


def emptyTheFile(filePath):
    if os.path.isfile(filePath):
        with open(filePath,'w') as file:
            file.write('')

def appendToFile(outputFile, text):
    with open(outputFile, 'a') as outFile:
        # print '---- ----- ----- ----- Writing {} to file {}'.format(text,outputFile)
        outFile.write(text+'\n')

def convertBasedOnMode(text, mode):
    if mode == 3:
        return text
    elif mode == 2:
        return text.upper()
    elif mode == 1:
        return text.lower()
    elif mode ==4 or mode == 5 :
        return text
    else:
        print 'Unacceptable text conversion mode'
        exit(2)

def isLetterInWord(line):
    chars = ['a','e','o','i','h','s','n','l','r','u','t','c','m']
    chars = ['a','e','o','i','h']
    chars1 = ['e','o','i','h']
    chars2 = ['s','n','l','r','u','t','c','m','d','p','b','g','y']
    # for char in chars:
    #     if char in line:
    # cvvcv
    # vvcvv
    # vvcvc

    data = line.strip()
    counter = 0
    if data[0] in chars2 and data[1] in chars and data[2] in chars and data[3] in chars2 and data[4] in chars:
        return True
    elif data[0] in chars1 and data[1] in chars1 and data[2] in chars2 and data[3] in chars and data[4] in chars:
        return True
    elif data[0] in chars1 and data[1] in chars1 and data[2] in chars2 and data[3] in chars and data[4] in chars2:
        return True
    else:
        return False


def processFile(masterFile, outputFile, convertMode, letterCount, maxLetterCount):
    global TOTAL_PROCESSED
    with open(masterFile,'r') as file:
        for line in file:
            # print 'Reading line {}'.format(line)
            if len(line.strip()) >= letterCount and len(line.strip()) <= maxLetterCount:
                if MODE == 4:
                    if re.match(REGEX_LOWER,line) and isLetterInWord(line):
                        TOTAL_PROCESSED = TOTAL_PROCESSED + 1
                        appendToFile(outputFile, convertBasedOnMode(line.strip(),convertMode))
                elif MODE == 5:
                    try:
                        if unicode(line.strip()).isalnum():
                            TOTAL_PROCESSED = TOTAL_PROCESSED + 1
                            appendToFile(outputFile, convertBasedOnMode(line.strip(),convertMode))
                    except Exception as e:
                        print "Unparsable"
                else:
                    appendToFile(outputFile, convertBasedOnMode(line.strip(),convertMode))
                    TOTAL_PROCESSED = TOTAL_PROCESSED + 1
                # print ' **** **** *** Word match for word {}'.format(line.strip())
                

def main():
    processArgs()
    emptyTheFile(OUTPUT_FILE)
    processFile(MASTERFILE, OUTPUT_FILE, MODE, LETTER_COUNT, MAX_LETTER_COUNT)
    print 'Processing Completed. \n{} words selected\n' \
          'Output file with {}-{} chars and mode {} can be found in path {}'.format(str(TOTAL_PROCESSED), str(LETTER_COUNT), str(MAX_LETTER_COUNT), str(MODE), OUTPUT_FILE)

main()
