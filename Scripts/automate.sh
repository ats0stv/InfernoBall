python preparePotForSubmission.py -d ../Hashes/Level10/pots/ -o team8_l10.out
mv -f team8_l10.pot ../Hashes/Level10/pots/
python ghost1.py -p ../Hashes/Level10/pots/team8_l10.pot -i ../00076-tsaregod-l10.as5 -s ../team08.secrets -o ../00076-tsaregod-l11.as5
python viren.py
