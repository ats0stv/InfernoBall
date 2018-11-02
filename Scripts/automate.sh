python preparePotForSubmission.py -d ../Hashes/Level5/pots/ -o team8_l5.out
mv -f team8_l5.pot ../Hashes/Level5/pots/
python ghost.py -p ../Hashes/Level5/pots/team8_l5.pot -i ../00076-tsaregod-l5.as5 -s ../team08.secrets -o ../00076-tsaregod-l6.as5
python viren.py
