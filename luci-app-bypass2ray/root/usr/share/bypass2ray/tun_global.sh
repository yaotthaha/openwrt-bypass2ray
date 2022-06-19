#!/bin/sh
###
gid="1010"
ipv4="1"
ipv6="1"
tun_name="tun_vpn"
###
IPSetName_PrivateV4="bypass2rayprivate4list"
IPSetName_PrivateV6="bypass2rayprivate6list"
###
IPT_M="iptables -t mangle"
IP6T_M="ip6tables -t mangle"
IPT_N="iptables -t nat"
IP6T_N="ip6tables -t nat"
IPT="iptables"
IP6T="ip6tables"

GenPrivateV4() {
    cat <<-EOF
        "10.0.0.0/8"
		"100.64.0.0/10"
		"192.88.99.0/24"
		"203.0.113.0/24"
		"0.0.0.0/8"
		"127.0.0.0/8"
		"198.18.0.0/15"
		"172.16.0.0/12"
		"192.0.0.0/24"
		"224.0.0.0/3"
		"169.254.0.0/16"
		"192.0.2.0/24"
		"192.168.0.0/16"
		"198.51.100.0/24"
EOF
}

GenPrivateV6() {
    cat <<-EOF
		::1/128
		::ffff:0:0/96
		::ffff:0:0:0/96
		64:ff9b::/96
		fc00::/7
		fe80::/10
		ff00::/8
EOF
}

CreateAndAddPrivateIPToIPSet() {
    if [ "$ipv4" = "1" ]; then
        ipset -! create $IPSetName_PrivateV4 nethash maxelem 1048576
        ipset -! -R <<-EOF
	        $(GenPrivateV4 | sed -e "s/^/add $IPSetName_PrivateV4 /")
EOF
    fi
    if [ "$ipv6" = "1" ]; then
        ipset -! create $IPSetName_PrivateV6 nethash family inet6 maxelem 1048576
        ipset -! -R <<-EOF
            $(GenPrivateV6 | sed -e "s/^/add $IPSetName_PrivateV6 /")
EOF
    fi
}

IPTables4Start() {
    $IPT_M -N TUN_MANGLE_PRE 2>/dev/null
    $IPT_M -F TUN_MANGLE_PRE
    $IPT_M -A TUN_MANGLE_PRE -i pppoe-wan -j RETURN
    $IPT_M -A TUN_MANGLE_PRE -m set --match-set $IPSetName_PrivateV4 dst -j RETURN
    $IPT_M -A TUN_MANGLE_PRE -p tcp -j MARK --set-mark 0x1
    $IPT_M -A TUN_MANGLE_PRE -p udp -j MARK --set-mark 0x1
    $IPT_M -I PREROUTING -j TUN_MANGLE_PRE
    $IPT_M -N TUN_MANGLE_OUT 2>/dev/null
    $IPT_M -F TUN_MANGLE_OUT
    $IPT_M -A TUN_MANGLE_OUT -m owner --gid-owner $gid -j RETURN
    $IPT_M -A TUN_MANGLE_OUT -m mark --mark 0xff -j RETURN
    $IPT_M -A TUN_MANGLE_OUT -m set --match-set $IPSetName_PrivateV4 dst -j RETURN
    $IPT_M -A TUN_MANGLE_OUT -p tcp -j MARK --set-mark 0x1
    $IPT_M -A TUN_MANGLE_OUT -p udp -j MARK --set-mark 0x1
    $IPT_M -I OUTPUT -j TUN_MANGLE_OUT
    ip route add 0.0.0.0/0 dev $tun_name table 100
    ip rule add fwmark 0x1 table 100
    $IPT_N -N TUN_NAT_POST 2>/dev/null
    $IPT_N -F TUN_NAT_POST
    $IPT_N -A TUN_NAT_POST -o $tun_name -j MASQUERADE
    $IPT_N -I POSTROUTING -j TUN_NAT_POST
    $IPT -N TUN_FOR 2>/dev/null
    $IPT -F TUN_FOR
    $IPT -A TUN_FOR -o $tun_name -j ACCEPT
    $IPT -I FORWARD -j TUN_FOR
}

IPTables6Start() {
    $IP6T_M -N TUN_MANGLE_PRE 2>/dev/null
    $IP6T_M -F TUN_MANGLE_PRE
    $IP6T_M -A TUN_MANGLE_PRE -i pppoe-wan -j RETURN
    $IP6T_M -A TUN_MANGLE_PRE -m set --match-set $IPSetName_PrivateV6 dst -j RETURN
    $IP6T_M -A TUN_MANGLE_PRE -p tcp -j MARK --set-mark 0x1
    $IP6T_M -A TUN_MANGLE_PRE -p udp -j MARK --set-mark 0x1
    $IP6T_M -I PREROUTING -j TUN_MANGLE_PRE
    $IP6T_M -N TUN_MANGLE_OUT 2>/dev/null
    $IP6T_M -F TUN_MANGLE_OUT
    $IP6T_M -A TUN_MANGLE_OUT -m owner --gid-owner $gid -j RETURN
    $IP6T_M -A TUN_MANGLE_OUT -m mark --mark 0xff -j RETURN
    $IP6T_M -A TUN_MANGLE_OUT -m set --match-set $IPSetName_PrivateV6 dst -j RETURN
    $IP6T_M -A TUN_MANGLE_OUT -p tcp -j MARK --set-mark 0x1
    $IP6T_M -A TUN_MANGLE_OUT -p udp -j MARK --set-mark 0x1
    $IP6T_M -I OUTPUT -j TUN_MANGLE_OUT
    ip -6 route add ::/0 dev $tun_name table 100
    ip -6 rule add fwmark 0x1 table 100
    $IP6T_N -N TUN_NAT_POST 2>/dev/null
    $IP6T_N -F TUN_NAT_POST
    $IP6T_N -A TUN_NAT_POST -o $tun_name -j MASQUERADE
    $IP6T_N -I POSTROUTING -j TUN_NAT_POST
    $IP6T -N TUN_FOR 2>/dev/null
    $IP6T -F TUN_FOR
    $IP6T -A TUN_FOR -o $tun_name -j ACCEPT
    $IP6T -I FORWARD -j TUN_FOR
}

IPTables4Stop() {
    $IPT_M -F TUN_MANGLE_PRE
    $IPT_M -X TUN_MANGLE_PRE
    $IPT_M -D PREROUTING -j TUN_MANGLE_PRE
    $IPT_M -F TUN_MANGLE_OUT
    $IPT_M -X TUN_MANGLE_OUT
    $IPT_M -D OUTPUT -j TUN_MANGLE_OUT
    ip route del 0.0.0.0/0 dev $tun_name table 100
    ip rule del fwmark 0x1 table 100
    $IPT_N -F TUN_NAT_POST
    $IPT_N -X TUN_NAT_POST
    $IPT_N -D POSTROUTING -j TUN_NAT_POST
    $IPT -F TUN_FOR
    $IPT -X TUN_FOR
    $IPT -D FORWARD -j TUN_FOR
}

IPTables6Stop() {
    $IP6T_M -F TUN_MANGLE_PRE
    $IP6T_M -X TUN_MANGLE_PRE
    $IP6T_M -D PREROUTING -j TUN_MANGLE_PRE
    $IP6T_M -F TUN_MANGLE_OUT
    $IP6T_M -X TUN_MANGLE_OUT
    $IP6T_M -D OUTPUT -j TUN_MANGLE_OUT
    ip -6 route del ::/0 dev $tun_name table 100
    ip -6 rule del fwmark 0x1 table 100
    $IP6T_N -F TUN_NAT_POST
    $IP6T_N -X TUN_NAT_POST
    $IP6T_N -D POSTROUTING -j TUN_NAT_POST
    $IP6T -F TUN_FOR
    $IP6T -X TUN_FOR
    $IP6T -D FORWARD -j TUN_FOR
}

IPSetDestroy() {
    ipset -! destroy $IPSetName_PrivateV4
    ipset -! destroy $IPSetName_PrivateV6
}

start() {
    CreateAndAddPrivateIPToIPSet
    if [ "$ipv4" = "1" ]; then
        IPTables4Start
    fi
    if [ "$ipv4" = "1" ]; then
        IPTables6Start
    fi
}

stop() {
    if [ "$ipv4" = "1" ]; then
        IPTables4Stop
    fi
    if [ "$ipv4" = "1" ]; then
        IPTables6Stop
    fi
    IPSetDestroy
}

case "$1" in
start)
    start
    ;;
stop)
    stop
    ;;
esac
