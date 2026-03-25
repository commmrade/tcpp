First first, do this: `iptables -A OUTPUT -p TCP --tcp-flags RST RST -j DROP`
First, start `tcpp`
Then start this test
