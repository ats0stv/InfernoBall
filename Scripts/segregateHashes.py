#/usr/bin/env python

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


"""	Script to Segregate the Hash Types
	Scalable Computing 
"""
__author__ = "Arun Thundyill Saseendran"
__version__ = "0.0.1"
__maintainer__ = "Arun Thundyill Saseendran"
__email__ = "thundyia@tcd.ie"


filename = "next.hashes"
newFilePrefix = "../Hashes/Level10/Split/level10"

formatDict = {"wierdhash":[],"descrypt":[]}
with open(filename, "r") as inputFile:
	for line in inputFile:
		if '$' in line:
			splittedLine = line.split('$')
			if len(splittedLine) > 1:
				if splittedLine[1] in formatDict:
					formatDict[splittedLine[1]].append(line)
				else:
					formatDict[splittedLine[1]] = [line]
			else:
				formatDict["wierdHash"].append(line)
		else:
			formatDict["descrypt"].append(line)

for key,value in formatDict.items():
	print key +"  "+ str(len(value))
	with open(newFilePrefix+"-"+key+".hashes","w") as outputFile:
		for item in value:
			outputFile.write(item)
