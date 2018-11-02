#/usr/bin/env python
"""	Script to Segregate the Hash Types
	Scalable Computing 
"""
__author__ = "Arun Thundyill Saseendran"
__version__ = "0.0.1"
__maintainer__ = "Arun Thundyill Saseendran"
__email__ = "thundyia@tcd.ie"


filename = "next.hashes"
newFilePrefix = "../Hashes/Level6/Split/level6"

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
