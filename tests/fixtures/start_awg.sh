#!/bin/bash
echo "Container startup"

# Apply container network tuning (see Dockerfile)
sysctl -p /etc/sysctl.conf 2>/dev/null || true

# Read subnet from server config dynamically (IPv4 part of the Address line)
SUBNET=$(grep '^Address' /opt/amnezia/awg/awg0.conf | head -1 | cut -d'=' -f2 | cut -d',' -f1 | tr -d ' ')
if [ -z "$SUBNET" ]; then
  SUBNET=10.8.1.1/24
fi

# IPv6 subnet, if the tunnel is dual-stack (second part of the Address line)
SUBNET6=$(grep '^Address' /opt/amnezia/awg/awg0.conf | head -1 | tr ',' '
' | grep ':' | sed 's/^[^=]*=//' | tr -d ' ' | head -1)

# kill daemons in case of restart
awg-quick down /opt/amnezia/awg/awg0.conf 2>/dev/null

# start daemons if configured
if [ -f /opt/amnezia/awg/awg0.conf ]; then awg-quick up /opt/amnezia/awg/awg0.conf; fi

# Allow traffic on the TUN interface
IFACE=$(basename /opt/amnezia/awg/awg0.conf .conf)
iptables -A INPUT -i $IFACE -j ACCEPT
iptables -A FORWARD -i $IFACE -j ACCEPT
iptables -A OUTPUT -o $IFACE -j ACCEPT

# Allow forwarding traffic only from the VPN
iptables -A FORWARD -i $IFACE -o eth0 -s $SUBNET -j ACCEPT
iptables -A FORWARD -i $IFACE -o eth1 -s $SUBNET -j ACCEPT

iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

iptables -t nat -A POSTROUTING -s $SUBNET -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s $SUBNET -o eth1 -j MASQUERADE

# IPv6 forwarding + NAT66, only when the tunnel has an IPv6 subnet
if [ -n "$SUBNET6" ] && command -v ip6tables >/dev/null 2>&1; then
  sysctl -w net.ipv6.conf.all.forwarding=1 2>/dev/null || true
  ip6tables -A INPUT -i $IFACE -j ACCEPT
  ip6tables -A FORWARD -i $IFACE -j ACCEPT
  ip6tables -A OUTPUT -o $IFACE -j ACCEPT
  ip6tables -A FORWARD -i $IFACE -o eth0 -s $SUBNET6 -j ACCEPT
  ip6tables -A FORWARD -i $IFACE -o eth1 -s $SUBNET6 -j ACCEPT
  ip6tables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
  ip6tables -t nat -A POSTROUTING -s $SUBNET6 -o eth0 -j MASQUERADE
  ip6tables -t nat -A POSTROUTING -s $SUBNET6 -o eth1 -j MASQUERADE
fi

# Apply per-peer bandwidth limits (flat file written by the panel)
if [ -f /opt/amnezia/awg/bwlimits ]; then
(

BW=/opt/amnezia/awg/bwlimits
IFACE=$(basename /opt/amnezia/awg/awg0.conf .conf)
[ -f "$BW" ] || exit 0
command -v tc >/dev/null 2>&1 || exit 0
ip link show dev $IFACE >/dev/null 2>&1 || exit 0
tc qdisc del dev $IFACE root 2>/dev/null
tc qdisc del dev $IFACE ingress 2>/dev/null
tc qdisc add dev $IFACE root handle 1: htb default 0 2>/dev/null || exit 0
tc qdisc add dev $IFACE handle ffff: ingress 2>/dev/null || true
i=0
while read -r ip4 ip6 mbps; do
  [ -z "$ip4" ] && continue
  [ -z "$mbps" ] && continue
  kbit=$(echo "$mbps" | awk '{printf "%d", $1*1000}')
  [ "$kbit" -gt 0 ] 2>/dev/null || continue
  i=$((i+1))
  cid=$((100+i))
  tc class add dev $IFACE parent 1: classid 1:$cid htb rate ${kbit}kbit ceil ${kbit}kbit 2>/dev/null
  tc filter add dev $IFACE parent 1: protocol ip u32 match ip dst $ip4/32 flowid 1:$cid 2>/dev/null
  [ "$ip6" != "-" ] && [ -n "$ip6" ] && tc filter add dev $IFACE parent 1: protocol ipv6 u32 match ip6 dst $ip6/128 flowid 1:$cid 2>/dev/null
  tc filter add dev $IFACE parent ffff: protocol ip u32 match ip src $ip4/32 police rate ${kbit}kbit burst 64k drop 2>/dev/null
  [ "$ip6" != "-" ] && [ -n "$ip6" ] && tc filter add dev $IFACE parent ffff: protocol ipv6 u32 match ip6 src $ip6/128 police rate ${kbit}kbit burst 64k drop 2>/dev/null
done < "$BW"

)
fi

tail -f /dev/null
