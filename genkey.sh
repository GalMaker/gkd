ssh-keygen -b 1536 -C -p -N "" -m pem -f ./id_rsa.pem
ssh-keygen -b 1536 -C -p -N "" -e -m pem -f ./id_rsa.pem > ./id_rsa.pem.pub
