python preparePotForSubmission.py -d ../Hashes/Level9/pots/ -o team8_l9.out
mv -f team8_l9.pot ../Hashes/Level9/pots/
python ghost1.py -p ../Hashes/Level9/pots/team8_l9.pot -i ../00076-tsaregod-l9.as5 -s ../team08.secrets -o ../00076-tsaregod-l10.as5
python viren.py
