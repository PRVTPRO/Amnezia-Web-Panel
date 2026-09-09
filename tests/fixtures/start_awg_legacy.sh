#!/bin/bash
echo "Container startup"

# Apply container network tuning (see Dockerfile)
sysctl -p /etc/sysctl.conf 2>/dev/null || true

# Read subnet from server config dynamically (IPv4 part of the Address line)
SUBNET=$(grep '^Address' /opt/amnezia/awg/wg0.conf | head -1 | cut -d'=' -f2 | cut -d',' -f1 | tr -d ' ')
if [ -z "$SUBNET" ]; then
  SUBNET=10.8.1.1/24
fi

# IPv6 subnet, if the tunnel is dual-stack (second part of the Address line)
SUBNET6=$(grep '^Address' /opt/amnezia/awg/wg0.conf | head -1 | tr ',' '
' | grep ':' | sed 's/^[^=]*=//' | tr -d ' ' | head -1)
# ---- Exit-node link (panel-managed; driven by /opt/amnezia/awg/exit/exit0.conf) ----
EXIT_CONF=/opt/amnezia/awg/exit/exit0.conf
EXIT_IF=exit0
EXIT_TABLE=200
EXIT_PREF=200      # slot 0: 190/191 exceptions, catch-all at the table number
DNS_NET=172.29.172.0/24
X_CONF=/opt/amnezia/awg/wg0.conf
X_QUICK=wg-quick
X_IFACE=$(basename $X_CONF .conf)
X_SUBNET=$(grep '^Address' $X_CONF | head -1 | cut -d'=' -f2 | cut -d',' -f1 | tr -d ' ')
[ -n "$X_SUBNET" ] || X_SUBNET=10.8.1.1/24
X_SUBNET6=$(grep '^Address' $X_CONF | head -1 | tr ',' '\n' | grep ':' | sed 's/^[^=]*=//' | tr -d ' ' | head -1)

x_rule()    { ip "$1" rule show 2>/dev/null | grep -q "^$2:" || ip "$1" rule add pref "$2" "${@:3}"; }
x_unrule()  { while ip "$1" rule del pref "$2" 2>/dev/null; do :; done; }
x_ipt_add() { iptables -t "$1" -C "${@:2}" 2>/dev/null || iptables -t "$1" -A "${@:2}"; }
x_ipt_del() { while iptables -t "$1" -D "${@:2}" 2>/dev/null; do :; done; }

x_killswitch_on() {
  # Everything from the client subnet is answered by the exit table. Until
  # exit0 is up that table holds only a blackhole, so nothing falls through
  # to eth0 - this runs before the client tunnel comes up on purpose.
  ip -4 route replace blackhole default metric 1000 table $EXIT_TABLE
  x_rule -4 190 from $X_SUBNET to $X_SUBNET lookup main
  if grep -qs '^# DnsViaExit = on' "$EXIT_CONF"; then x_unrule -4 191
  else x_rule -4 191 from $X_SUBNET to $DNS_NET lookup main; fi
  x_rule -4 $EXIT_PREF from $X_SUBNET lookup $EXIT_TABLE
  if [ -n "$X_SUBNET6" ]; then
    # No IPv6 path through the exit yet: refuse fast instead of leaking via eth0
    ip -6 route replace unreachable default table $EXIT_TABLE
    x_rule -6 190 from $X_SUBNET6 to $X_SUBNET6 lookup main
    x_rule -6 $EXIT_PREF from $X_SUBNET6 lookup $EXIT_TABLE
  fi
}
x_killswitch_off() {
  for p in 190 191 $EXIT_PREF; do x_unrule -4 $p; x_unrule -6 $p; done
  ip -4 route flush table $EXIT_TABLE 2>/dev/null
  ip -6 route flush table $EXIT_TABLE 2>/dev/null
}
x_link_up() {
  $X_QUICK down $EXIT_CONF 2>/dev/null
  if ! $X_QUICK up $EXIT_CONF; then
    echo "! $EXIT_IF failed to start; clients stay on the kill-switch until the link is repaired or removed"
    return 3
  fi
  # Loose reverse-path check on the link only: containers inherit rp_filter
  # from the host, and per-client exit tables (later) can make the reverse
  # lookup resolve to another exitN.
  sysctl -w net.ipv4.conf.$EXIT_IF.rp_filter=2 >/dev/null 2>&1 || true
  ip -4 route replace default dev $EXIT_IF table $EXIT_TABLE
  x_ipt_add filter FORWARD -i $X_IFACE -o $EXIT_IF -s $X_SUBNET -j ACCEPT
  # SNAT clients into this node's transit address: the exit sees one /32 per entry
  x_ipt_add nat POSTROUTING -s $X_SUBNET -o $EXIT_IF -j MASQUERADE
  x_ipt_add mangle FORWARD -o $EXIT_IF -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
  x_ipt_add mangle FORWARD -i $EXIT_IF -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
  # NAT is decided once per flow: flows opened before the link were SNATed to
  # eth0 and would leave exit0 with the wrong source. Drop them so they reopen.
  if command -v conntrack >/dev/null 2>&1; then conntrack -D -s $X_SUBNET >/dev/null 2>&1
  else echo "! conntrack-tools missing: client flows opened before the link keep leaving via eth0 until they end"; fi
  # Never report success while clients could still leave via eth0
  if ! ip -4 rule show | grep -q "^$EXIT_PREF:" \
     || ! ip -4 route show table $EXIT_TABLE | grep -q "^default dev $EXIT_IF" \
     || ! iptables -t nat -C POSTROUTING -s $X_SUBNET -o $EXIT_IF -j MASQUERADE 2>/dev/null; then
    echo "! FATAL: policy routing for $EXIT_IF is not in place"
    return 3
  fi
  echo "exit link up: $(ip -4 -o addr show dev $EXIT_IF | awk '{print $4}') -> table $EXIT_TABLE"
}
x_link_down() {
  # Take the interface down first: MASQUERADE forgets the flows NATed through
  # it (device notifier) and the table keeps blackholing until the rules go.
  [ -f "$EXIT_CONF" ] && $X_QUICK down $EXIT_CONF 2>/dev/null
  ip link del $EXIT_IF 2>/dev/null
  x_ipt_del filter FORWARD -i $X_IFACE -o $EXIT_IF -s $X_SUBNET -j ACCEPT
  x_ipt_del nat POSTROUTING -s $X_SUBNET -o $EXIT_IF -j MASQUERADE
  x_ipt_del mangle FORWARD -o $EXIT_IF -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
  x_ipt_del mangle FORWARD -i $EXIT_IF -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
}
x_exit_sync() {
  if [ -f "$EXIT_CONF" ]; then x_killswitch_on && x_link_up
  else x_link_down; x_killswitch_off; fi
}
[ -f "$EXIT_CONF" ] && x_killswitch_on


# kill daemons in case of restart
wg-quick down /opt/amnezia/awg/wg0.conf 2>/dev/null

# start daemons if configured
if [ -f /opt/amnezia/awg/wg0.conf ]; then wg-quick up /opt/amnezia/awg/wg0.conf; fi

# Allow traffic on the TUN interface
IFACE=$(basename /opt/amnezia/awg/wg0.conf .conf)
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
IFACE=$(basename /opt/amnezia/awg/wg0.conf .conf)
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

# ---- Exit-node link: bring it up now that the client tunnel exists ----
if [ -f "$EXIT_CONF" ]; then x_link_up || echo "! exit link not applied, clients stay on the kill-switch"; fi

tail -f /dev/null
