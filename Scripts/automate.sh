python preparePotForSubmission.py -d ../Hashes/Level8/pots/ -o team8_l8.out
mv -f team8_l8.pot ../Hashes/Level8/pots/
python ghost1.py -p ../Hashes/Level8/pots/team8_l8.pot -i ../00076-tsaregod-l8.as5 -s ../team08.secrets -o ../00076-tsaregod-l9.as5
python viren.py
