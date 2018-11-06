


FILE='./names.potfile'
OUTPUT = './submitty.words'

master = []
print 'Start'
count = 0
try:
	with open(FILE,'r') as file:
		print 'File Opened'
		for line in file:
			print line
			if ':' in line:
				split = line.split(':')
				print split[1]
				uname = split[1].replace('$HEX[', '')
				print 'Replace HEX'
				uname = uname.replace(']', '')
				uname = str(uname)
				master.append(uname)
				count = count +1
except Exception as e:
	print e

print 'Total' + str(count)
with open(OUTPUT, 'w') as out:
	for line in master:
		out.write(line)



