#!/bin/bash -x

[[ $# -lt 2 ]] && echo "Usage: $0 <VxLAN> <remote.pub.ip:port> [ip-net.txt ...]" && exit 255

VLAN_ID=$(echo $1 | tr -d '[A-Za-z]+')
[[ "$VLAN_ID" != "$(( $VLAN_ID / 1 ))" ]] && echo "VLAN_ID:\"$1\" must suffix with a number!" && exit 254

TUN_DEV=$1
REMOTE_INT="192.168.2.$(( $VLAN_ID % 64 * 4 + 1 ))"
LOCAL_INT="192.168.2.$(( $VLAN_ID % 64 * 4 + 2 ))/30"
REMOTE_NS=$(host -t a ${2%:*})
REMOTE_IP4=${REMOTE_NS##* }
REMOTE_PORT=${2##*:}
TABLE_ID=$((VLAN_ID+80))

## VxLAN
ip link del $TUN_DEV 2>/dev/null
ip link add $TUN_DEV type vxlan id $TABLE_ID remote $REMOTE_IP4 ttl 64 dstport $REMOTE_PORT dev eth0

sysctl -w net.ipv6.conf.$TUN_DEV.disable_ipv6=1
sysctl -w net.ipv4.conf.$TUN_DEV.rp_filter=2

ip link set $TUN_DEV mtu 1416
ip addr add $LOCAL_INT dev $TUN_DEV
ip link set $TUN_DEV up

## Add route
ip route add default via $REMOTE_INT dev $TUN_DEV metric 99 table $TABLE_ID
ip route add default via $REMOTE_INT dev $TUN_DEV metric $((VLAN_ID+2000))

## Additional routes
shift 2
[[ $# -gt 0 ]] && grep -h -v -E '^\s*#' $* | while read net;do
  [[ -n "${net// }" ]] && ip route replace $net metric 100 via $REMOTE_INT dev $TUN_DEV || \
    ip route add $net metric 100 via $REMOTE_INT dev $TUN_DEV
done

exit 0

