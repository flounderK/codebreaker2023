#!/bin/sh

git clone https://github.com/glv2/bruteforce-luks.git

cd bruteforce-luks
./autogen.sh
./configure
make

# cat << EOF > ~/start_cmd.sh
# #!/bin/sh
# ~/bruteforce-luks/bruteforce-luks -f $@ -v 30 ~/part.enc -w ~/bruteforce_state
# EOF

chmod +x ~/start_cmd.sh
