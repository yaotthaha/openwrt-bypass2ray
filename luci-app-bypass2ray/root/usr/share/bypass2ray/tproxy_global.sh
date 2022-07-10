#!/bin/sh
###
tproxy_port="12345"
gid="1010"
ipv4="1"
ipv6="1"
###
IPSetName_PrivateV4="bypass2rayprivate4list"
IPSetName_PrivateV6="bypass2rayprivate6list"
###
IPT_M="iptables -t mangle"
IP6T_M="ip6tables -t mangle"

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
    $IPT_M -N TPROXY_PRE 2>/dev/null
    $IPT_M -F TPROXY_PRE
    #$IPT_M -A TPROXY_PRE -i pppoe-wan -j RETURN
    $IPT_M -A TPROXY_PRE -j CONNMARK --restore-mark
    $IPT_M -A TPROXY_PRE -m mark --mark 0xff -j RETURN
    $IPT_M -A TPROXY_PRE -m set --match-set $IPSetName_PrivateV4 dst -j RETURN
    $IPT_M -A TPROXY_PRE -p tcp -j TPROXY --on-port $tproxy_port --tproxy-mark 0x1/0x1
    $IPT_M -A TPROXY_PRE -p udp -j TPROXY --on-port $tproxy_port --tproxy-mark 0x1/0x1
    $IPT_M -I PREROUTING -j TPROXY_PRE
    $IPT_M -N TPROXY_OUT 2>/dev/null
    $IPT_M -F TPROXY_OUT
    $IPT_M -A TPROXY_OUT -m owner --gid-owner $gid -j MARK --set-mark 0xff
    $IPT_M -A TPROXY_OUT -j CONNMARK --save-mark
    $IPT_M -A TPROXY_OUT -m mark --mark 0xff -j RETURN
    $IPT_M -A TPROXY_OUT -m set --match-set $IPSetName_PrivateV4 dst -j RETURN
    $IPT_M -A TPROXY_OUT -p tcp -j MARK --set-mark 1
    $IPT_M -A TPROXY_OUT -p udp -j MARK --set-mark 1
    $IPT_M -I OUTPUT -j TPROXY_OUT
    ip route add local default dev lo table 100
    ip rule add fwmark 1 table 100
    $IPT_M -N TPROXY_DIV 2>/dev/null
    $IPT_M -F TPROXY_DIV
    $IPT_M -A TPROXY_DIV -j MARK --set-mark 1
    $IPT_M -A TPROXY_DIV -j ACCEPT
    $IPT_M -I PREROUTING -p tcp -m socket -j TPROXY_DIV
}

IPTables4Stop() {
    ip route del local default dev lo table 100
    ip rule del fwmark 1 table 100
    $IPT_M -D PREROUTING -j TPROXY_PRE
    $IPT_M -D OUTPUT -j TPROXY_OUT
    $IPT_M -D PREROUTING -p tcp -m socket -j TPROXY_DIV
    $IPT_M -F TPROXY_PRE
    $IPT_M -X TPROXY_PRE
    $IPT_M -F TPROXY_OUT
    $IPT_M -X TPROXY_OUT
    $IPT_M -F TPROXY_DIV
    $IPT_M -X TPROXY_DIV
}

IPTables6Start() {
    $IP6T_M -N TPROXY_PRE 2>/dev/null
    $IP6T_M -F TPROXY_PRE
    #$IP6T_M -A TPROXY_PRE -i pppoe-wan -j RETURN
    $IP6T_M -A TPROXY_PRE -j CONNMARK --restore-mark
    $IP6T_M -A TPROXY_PRE -m mark --mark 0xff -j RETURN
    $IP6T_M -A TPROXY_PRE -m set --match-set $IPSetName_PrivateV6 dst -j RETURN
    $IP6T_M -A TPROXY_PRE -p tcp -j TPROXY --on-port $tproxy_port --tproxy-mark 0x1/0x1
    $IP6T_M -A TPROXY_PRE -p udp -j TPROXY --on-port $tproxy_port --tproxy-mark 0x1/0x1
    $IP6T_M -I PREROUTING -j TPROXY_PRE
    $IP6T_M -N TPROXY_OUT 2>/dev/null
    $IP6T_M -F TPROXY_OUT
    $IP6T_M -A TPROXY_OUT -m owner --gid-owner $gid -j MARK --set-mark 0xff
    $IP6T_M -A TPROXY_OUT -j CONNMARK --save-mark
    $IP6T_M -A TPROXY_OUT -m mark --mark 0xff -j RETURN
    $IP6T_M -A TPROXY_OUT -m set --match-set $IPSetName_PrivateV6 dst -j RETURN
    $IP6T_M -A TPROXY_OUT -p tcp -j MARK --set-mark 1
    $IP6T_M -A TPROXY_OUT -p udp -j MARK --set-mark 1
    $IP6T_M -I OUTPUT -j TPROXY_OUT
    ip -6 route add local default dev lo table 100
    ip -6 rule add fwmark 1 table 100
    $IP6T_M -N TPROXY_DIV 2>/dev/null
    $IP6T_M -F TPROXY_DIV
    $IP6T_M -A TPROXY_DIV -j MARK --set-mark 1
    $IP6T_M -A TPROXY_DIV -j ACCEPT
    $IP6T_M -I PREROUTING -p tcp -m socket -j TPROXY_DIV
}

IPTables6Stop() {
    ip -6 route del local default dev lo table 100
    ip -6 rule del fwmark 1 table 100
    $IP6T_M -D PREROUTING -j TPROXY_PRE
    $IP6T_M -D OUTPUT -j TPROXY_OUT
    $IP6T_M -D PREROUTING -p tcp -m socket -j TPROXY_DIV
    $IP6T_M -F TPROXY_PRE
    $IP6T_M -X TPROXY_PRE
    $IP6T_M -F TPROXY_OUT
    $IP6T_M -X TPROXY_OUT
    $IP6T_M -F TPROXY_DIV
    $IP6T_M -X TPROXY_DIV
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
