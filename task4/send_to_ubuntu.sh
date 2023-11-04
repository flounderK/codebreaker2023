#!/bin/bash

if [ $# -lt 2 ]; then
	echo "usage: $0 <ip-addr> <hash_file>"
	exit 1
fi

ssh-copy-id root@$1
scp ~/setup_root.sh root@$1:/root/
ssh root@$1 'chmod +x /root/setup_root.sh'
ssh root@$1 'sh /root/setup_root.sh'

scp ~/codebreaker23/task4/part.enc ubuntu@$1:~/
scp $2 ubuntu@$1:~/
scp ~/setup_ubuntu.sh ubuntu@$1:~/


HASH_FILE_NAME=$(basename $2)

cat << EOF > ~/start_cmd.sh
#!/bin/sh
~/bruteforce-luks/bruteforce-luks -t 8 -f ~/$HASH_FILE_NAME -v 30 ~/part.enc -w ~/bruteforce_state
EOF

chmod +x ~/start_cmd.sh

scp ~/start_cmd.sh ubuntu@$1:~/

ssh ubuntu@$1 'chmod +x ~/setup_ubuntu.sh'
ssh ubuntu@$1 'sh ~/setup_ubuntu.sh'

