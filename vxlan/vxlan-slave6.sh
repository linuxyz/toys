#!/bin/bash -x

[[ $# -lt 2 ]] && echo "Usage: $0 <VxLAN> <remote.pub6.name:port> [ip-net.txt ...]" && exit 255

VLAN_ID=$(echo $1 | tr -d '[A-Za-z]+')
[[ "$VLAN_ID" != "$(( $VLAN_ID / 1 ))" ]] && echo "VLAN_ID:\"$1\" must suffix with a number!" && exit 254

TUN_DEV=$1
REMOTE_INT="192.168.2.$(( $VLAN_ID % 64 * 4 + 1 ))"
LOCAL_INT="192.168.2.$(( $VLAN_ID % 64 * 4 + 2 ))/30"
REMOTE_NS=$(host -6 -t aaaa ${2%:*})
REMOTE_IP6=${REMOTE_NS##* }
REMOTE_PORT=${2##*:}
#MY_IP6=$(ifstatus wan_6 | jsonfilter -e '@["ipv6-address"][0].address')
TABLE_ID=$((VLAN_ID+80))

## VxLAN
ip link del $TUN_DEV 2>/dev/null
ip -6 link add $TUN_DEV type vxlan id $TABLE_ID remote $REMOTE_IP6 ttl 64 dstport $REMOTE_PORT dev eth0

sysctl -w net.ipv6.conf.$TUN_DEV.disable_ipv6=1
sysctl -w net.ipv4.conf.$TUN_DEV.rp_filter=0

ip link set $TUN_DEV mtu 1416
ip addr add $LOCAL_INT dev $TUN_DEV
ip link set $TUN_DEV up

## Add route
ip route add default via $REMOTE_INT metric 99 table $TABLE_ID dev $TUN_DEV
ip route add default via $REMOTE_INT metric $((VLAN_ID+2000)) dev $TUN_DEV

## Additional routes
shift 2
[[ $# -gt 0 ]] && grep -h -v -E '^\s*#' $* | while read net;do
  [[ -n "${net// }" ]] && ip route add $net via $REMOTE_INT metric 200 dev $TUN_DEV
done

exit 0

