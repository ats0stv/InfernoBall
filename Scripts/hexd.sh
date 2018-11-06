input="./submitty.words"
while IFS= read -r var
do
  echo $var | xxd -r -p
done < "$input"
