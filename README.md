# ethkeydump

rsync the keystore directory over from the server

```
rsync -av user@cloud:/home/user/keystore ./

for keyfile in keystore/*; do cat $keyfile | ./ethkeydump the_hard_to_break_password && printf "\tsuccess\n" || printf "\tfailed\n"; done
``` 

