python preparePotForSubmission.py -d ../Hashes/Level7/pots/ -o team8_l7.out
mv -f team8_l7.pot ../Hashes/Level7/pots/
python ghost.py -p ../Hashes/Level7/pots/team8_l7.pot -i ../00076-tsaregod-l7.as5 -s ../team08.secrets -o ../00076-tsaregod-l8.as5
python viren.py
