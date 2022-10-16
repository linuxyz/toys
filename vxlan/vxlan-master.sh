#!/bin/bash -x

[[ $# -lt 3 ]] && echo "Usage: $0 <VxLAN> <udp-port> <remote.pub.ip4> [remote.lan.ip4/net] " && exit 255

VLAN_ID=$(echo $1 | tr -d '[A-Za-z]+')
[[ "$VLAN_ID" != "$(( $VLAN_ID / 1 ))" ]] && echo "VLAN_ID:\"$1\" must suffix with a number!" && exit 254

TUN_DEV=$1
LOCAL_INT="192.168.2.$(( $VLAN_ID % 64 * 4 + 1 ))/30"
REMOTE_INT="192.168.2.$(( $VLAN_ID % 64 * 4 + 2 ))"
REMOTE_PORT=$2
REMOTE_IP=$3 #{3:-$(echo $SSH_CLIENT | cut -d' ' -f1)}
MY_IPS=$(hostname -I)
MY_IP4=${MY_IPS%% *}
TABLE_ID=$((VLAN_ID+80))

[[ -z "$REMOTE_IP" ]] && echo "Error: remote.put.ip4 not specified!" && exit 253

## FOU6
ip link del $TUN_DEV
ip link add $TUN_DEV type vxlan id $TABLE_ID remote $REMOTE_IP ttl 64 dstport $REMOTE_PORT

sysctl -w net.ipv6.conf.$TUN_DEV.disable_ipv6=1
sysctl -w net.ipv4.conf.$TUN_DEV.rp_filter=2

ip link set $TUN_DEV mtu 1416
ip addr add $LOCAL_INT dev $TUN_DEV
ip link set $TUN_DEV up
ip route add default via ${LOCAL_INT%%/*} metric $((VLAN_ID+1000)) dev $TUN_DEV

## All remote iP/net
shift 3
# Add all the given subnet to SNAT
for net in $*;do
  ip route add $net via $REMOTE_INT metric 300 dev $TUN_DEV
done

exit 0

