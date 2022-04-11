local dsp = require "luci.dispatcher"
local nixio = require "nixio"
local util = require "luci.util"
local appname = require "luci.model.cbi.bypass2ray.support".appname
local m, s, o

local uuid = arg[1]

m = Map(appname, "%s - %s" % { translate("ByPass2Ray"), translate("Edit Outbound") })
m.redirect = dsp.build_url("admin/services/" .. appname .. "/outbound")

if m.uci:get(appname, uuid) ~= "outbound" then
	luci.http.redirect(m.redirect)
	return
end

local allow_choose_listen_ips = { "0.0.0.0", "127.0.0.1", "::", "" }

for _, v in ipairs(nixio.getifaddrs()) do
	if v.addr and
		(v.family == "inet" or v.family == "inet6") and
		v.name ~= "lo" and
		not util.contains(allow_choose_listen_ips, v.addr)
	then
		util.append(allow_choose_listen_ips, v.addr)
	end
end

s = m:section(NamedSection, uuid, "outbound")
--s.anonymous = true
s.addremove = false
s.dynamic = false

---

o = s:option(Value, "alias", translate("Alias"))
o.rmempty = false

o = s:option(Flag, "enable", translate("Enable"))
o.default = false

o = s:option(Value, "sendthrough", translate("SendThrough"))
o.datatype = "ipaddr"

protocol = s:option(ListValue, "protocol", translate("Protocol"))
protocol:value("blackhole", translate("Blackhole"))
protocol:value("freedom", "Freedom")
protocol:value("dns", "DNS")
protocol:value("http", "HTTP")
protocol:value("socks", "Socks")
protocol:value("vmess", "VMess")
protocol:value("shadowsocks", "ShadowSocks")
protocol:value("trojan", "Trojan")
protocol:value("vless", "VLESS")

-- Settings - Blackhole
o = s:option(ListValue, "settings_blackhole_response_type", "%s - %s" % { "Blackhole", translate("Response Type") })
o:depends("protocol", "blackhole")
o:value("")
o:value("none", "None")
o:value("http", "HTTP")

-- Settings - Freedom
o = s:option(ListValue, "settings_freedom_domainstrategy", "%s - %s" % { "Freedom", translate("DomainStrategy") })
o:depends("protocol", "freedom")
o:value("")
o:value("AsIs")
o:value("UseIP")
o:value("UseIPv4")
o:value("UseIPv6")

o = s:option(Value, "settings_freedom_redirect", "%s - %s" % { "Freedom", translate("Redirect") }, translate("Force send all data to this address"))
o:depends("protocol", "freedom")

-- Settings - DNS
o = s:option(ListValue, "settings_dns_network", "%s - %s" % { "DNS", translate("Network") })
o:depends("protocol", "dns")
o:value("tcp", "TCP")
o:value("udp", "UDP")

o = s:option(Value, "settings_dns_address", "%s - %s" % { "DNS", translate("Address") }, translate("DNS Server Address"))
o:depends("protocol", "dns")
o.datatype = "ipaddr"

o = s:option(Value, "settings_dns_port", "%s - %s" % { "DNS", translate("Port") }, translate("DNS Server Port"))
o:depends("protocol", "dns")
o.datatype = "port"

-- Settings - HTTP
o = s:option(Value, "settings_http_servers_address", "%s - %s" % { "HTTP", translate("Address") })
o:depends("protocol", "http")
o.rmempty = false

o = s:option(Value, "settings_http_servers_port", "%s - %s" % { "HTTP", translate("Port") })
o:depends("protocol", "http")
o.datatype = "port"
o.rmempty = false

o = s:option(Value, "settings_http_servers_users_user", "%s - %s" % { "HTTP", translate("User") })
o:depends("protocol", "http")

o = s:option(Value, "settings_http_servers_users_pass", "%s - %s" % { "HTTP", translate("Pass") })
o:depends("protocol", "http")
o.password = true

-- Settings - Socks
o = s:option(Value, "settings_socks_servers_address", "%s - %s" % { "Socks", translate("Address") })
o:depends("protocol", "socks")
o.rmempty = false

o = s:option(Value, "settings_socks_servers_port", "%s - %s" % { "Socks", translate("Port") })
o:depends("protocol", "socks")
o.datatype = "port"
o.rmempty = false

o = s:option(Value, "settings_socks_servers_users_user", "%s - %s" % { "Socks", translate("User") })
o:depends("protocol", "socks")

o = s:option(Value, "settings_socks_servers_users_pass", "%s - %s" % { "Socks", translate("Pass") })
o:depends("protocol", "socks")
o.password = true

-- Settings - VMess
o = s:option(Value, "settings_vmess_vnext_address", "%s - %s" % { "VMess", translate("Address") })
o:depends("protocol", "vmess")
o.rmempty = false

o = s:option(Value, "settings_vmess_vnext_port", "%s - %s" % { "VMess", translate("Port") })
o:depends("protocol", "vmess")
o.datatype = "port"
o.rmempty = false

o = s:option(Value, "settings_vmess_vnext_users_id", "%s - %s" % { "VMess", "ID" })
o:depends("protocol", "vmess")
o.rmempty = false

o = s:option(Value, "settings_vmess_vnext_users_alterid", "%s - %s" % { "VMess", "alterId" })
o:depends("protocol", "vmess")
o.datatype = "and(uinteger, max(65535))"

o = s:option(ListValue, "settings_vmess_vnext_users_security", "%s - %s" % { "VMess", "Security" })
o:depends("protocol", "vmess")
o:value("")
o:value("auto")
o:value("aes-128-gcm")
o:value("chacha20-poly1305")
o:value("none")
o:value("zero")

-- Settings - ShadowSocks
o = s:option(Value, "settings_shadowsocks_servers_address", "%s - %s" % { "ShadowSocks", translate("Address") })
o:depends("protocol", "shadowsocks")
o.rmempty = false

o = s:option(Value, "settings_shadowsocks_servers_port", "%s - %s" % { "ShadowSocks", translate("Port") })
o:depends("protocol", "shadowsocks")
o.datatype = "port"
o.rmempty = false

o = s:option(ListValue, "settings_shadowsocks_servers_method", "%s - %s" % { "ShadowSocks", translate("Method") },
    translate("aes-256-cfb, aes-128-cfb, chacha20, chacha20-ietf Xray Support"))
o:depends("protocol", "shadowsocks")
o:value("")
o:value("none")
o:value("aes-256-cfb")
o:value("aes-128-cfb")
o:value("chacha20")
o:value("chacha20-ietf")
o:value("aes-256-gcm")
o:value("aes-128-gcm")
o:value("chacha20-poly1305")
o:value("chacha20-ietf-poly1305")

o = s:option(Value, "settings_shadowsocks_servers_password", "%s - %s" % { "ShadowSocks", translate("Password") })
o:depends("protocol", "shadowsocks")
o.password = true
o.rmempty = false

o = s:option(Flag, "settings_shadowsocks_servers_ivCheck", "%s - %s" % { "ShadowSocks", translate("ivCheck") })
o:depends("protocol", "shadowsocks")

-- Settings - Trojan
o = s:option(Value, "settings_trojan_servers_address", "%s - %s" % { "Trojan", translate("Address") })
o:depends("protocol", "trojan")
o.rmempty = false

o = s:option(Value, "settings_trojan_servers_port", "%s - %s" % { "Trojan", translate("Port") })
o:depends("protocol", "trojan")
o.datatype = "port"
o.rmempty = false

o = s:option(Value, "settings_trojan_servers_password", "%s - %s" % { "Trojan", translate("Password") })
o:depends("protocol", "trojan")
o.password = true
o.rmempty = false

trojan_flow = s:option(ListValue, "settings_trojan_servers_flow", "%s - %s" % { "Trojan", translate("Flow") },
    translate("Only Xray Support"))
trojan_flow:depends("protocol", "trojan")
trojan_flow:value("", translate("None"))
trojan_flow:value("xtls-rprx-origin")
trojan_flow:value("xtls-rprx-origin-udp443")
trojan_flow:value("xtls-rprx-direct")
trojan_flow:value("xtls-rprx-direct-udp443")
trojan_flow:value("xtls-rprx-splice")
trojan_flow:value("xtls-rprx-splice-udp443")

-- Settings - VLESS
o = s:option(Value, "settings_vless_vnext_address", "%s - %s" % { "VLESS", translate("Address") })
o:depends("protocol", "vless")
o.rmempty = false

o = s:option(Value, "settings_vless_vnext_port", "%s - %s" % { "VLESS", translate("Port") })
o:depends("protocol", "vless")
o.datatype = "port"
o.rmempty = false

o = s:option(Value, "settings_vless_vnext_users_id", "%s - %s" % { "VLESS", "ID" })
o:depends("protocol", "vless")
o.rmempty = false

o = s:option(ListValue, "settings_vless_vnext_users_encryption", "%s - %s" % { "VLESS", translate("Encryption") })
o:depends("protocol", "vless")
o:value("")
o:value("none")

vless_flow = s:option(ListValue, "settings_vless_vnext_servers_flow", "%s - %s" % { "VLESS", translate("Flow") },
    translate("Only Xray Support"))
vless_flow:depends("protocol", "vless")
vless_flow:value("")
vless_flow:value("xtls-rprx-origin")
vless_flow:value("xtls-rprx-origin-udp443")
vless_flow:value("xtls-rprx-direct")
vless_flow:value("xtls-rprx-direct-udp443")
vless_flow:value("xtls-rprx-splice")
vless_flow:value("xtls-rprx-splice-udp443")
vless_flow:value("", translate("None"))

o = s:option(Value, "tag", translate("Tag"))

o = s:option(Value, "ps_tag", "%s - %s" % { "ProxySettings", translate("Tag") })

o = s:option(Flag, "mux_enable", "%s - %s" % { "Mux", translate("Enable") })

o = s:option(Value, "mux_concurrency", "%s - %s" % { "Mux", translate("Concurrency") })
o:depends("mux_enable", true)
o.datatype = "and(uinteger, min(1), max(1024))"

-- StreamSettings - Network
o = s:option(ListValue, "ss_network", "%s - %s" % { translate("Stream settings"), translate("Network") })
o:value("")
o:value("tcp")
o:value("kcp")
o:value("ws")
o:value("http")
--o:value("domainsocket")
o:value("quic")
o:value("grpc")

-- StreamSettings - Security
o = s:option(ListValue, "ss_security_tls_enable", "%s - %s" % { translate("Stream settings"), translate("Security") },
	translate("If Flow isn't nil, then tls change to xtls"))
o:value("", translate("None"))
o:value("tls", translate("(X)TLS"))

-- StreamSettings - (X)TLS
o = s:option(Value, "ss_tls_servername", "%s - %s" % { translate("(X)TLS"), translate("ServerName") })
o:depends("ss_security_tls_enable", "tls")

o = s:option(Flag, "ss_tls_rejectunknownsni", "%s - %s" % { translate("(X)TLS"), translate("RejectUnknownSni") })
o:depends("ss_security_tls_enable", "tls")

o = s:option(Flag, "ss_tls_allowinsecure", "%s - %s" % { translate("(X)TLS"), translate("AllowInsecure") })
o:depends("ss_security_tls_enable", "tls")

o = s:option(MultiValue, "ss_tls_alpn", "%s - %s" % { translate("(X)TLS"), translate("ALPN") })
o:depends("ss_security_tls_enable", "tls")
o:value("h2")
o:value("http/1.1")

o = s:option(ListValue, "ss_tls_minversion", "%s - %s" % { translate("(X)TLS"), translate("MinVersion") })
o:depends("ss_security_tls_enable", "tls")
o:value("")
o:value("1.1")
o:value("1.2")
o:value("1.3")

o = s:option(ListValue, "ss_tls_maxversion", "%s - %s" % { translate("(X)TLS"), translate("MaxVersion") })
o:depends("ss_security_tls_enable", "tls")
o:value("")
o:value("1.1")
o:value("1.2")
o:value("1.3")

o = s:option(DynamicList, "ss_tls_ciphersuites", "%s - %s" % { translate("(X)TLS"), translate("cipherSuites") })
o:depends("ss_security_tls_enable", "tls")

o = s:option(Flag, "ss_tls_disablesystemroot", "%s - %s" % { translate("(X)TLS"), translate("DisableSystemRoot") })
o:depends("ss_security_tls_enable", "tls")

o = s:option(Flag, "ss_tls_enablesessionresumption", "%s - %s" % { translate("(X)TLS"), translate("EnableSessionResumption") })
o:depends("ss_security_tls_enable", "tls")

o = s:option(ListValue, "ss_tls_fingerprint", "%s - %s" % { translate("(X)TLS"), translate("Fingerprint") })
o:depends("ss_security_tls_enable", "tls")
o:value("", translate("None"))
o:value("chrome")
o:value("firefox")
o:value("safari")
o:value("randomized")

o = s:option(Value, "ss_tls_certificates_ocspstapling", "%s - %s" % { translate("(X)TLS Certificates"), translate("OcspStapling") })
o:depends("ss_security_tls_enable", "tls")
o.datatype = "uinteger"

o = s:option(Flag, "ss_tls_certificates_onetimeloading", "%s - %s" % { translate("(X)TLS Certificates"), translate("OneTimeLoading") })
o:depends("ss_security_tls_enable", "tls")

o = s:option(ListValue, "ss_tls_certificates_usage", "%s - %s" % { translate("(X)TLS Certificates"), translate("Usage") })
o:depends("ss_security_tls_enable", "tls")
o:value("")
o:value("encipherment")
o:value("verify")
o:value("issue")

o = s:option(Value, "ss_tls_certificates_certificatefile", "%s - %s" % { translate("(X)TLS Certificates"), translate("CertificateFile") })
o:depends("ss_security_tls_enable", "tls")

o = s:option(Value, "ss_tls_certificates_keyfile", "%s - %s" % { translate("(X)TLS Certificates"), translate("KeyFile") })
o:depends("ss_security_tls_enable", "tls")

-- StreamSettings - TCP
o = s:option(ListValue, "ss_tcp_header_type", "%s - %s" % { translate("TCP"), translate("Header Type") })
o:depends("ss_network", "tcp")
o:value("none", translate("None"))
o:value("http")

o = s:option(Value, "ss_tcp_header_request_version", "%s - %s" % { translate("TCP"), translate("Header Request Version") })
o:depends("ss_tcp_header_type", "http")

o = s:option(Value, "ss_tcp_header_request_method", "%s - %s" % { translate("TCP"), translate("Header Request Method") })
o:depends("ss_tcp_header_type", "http")

o = s:option(DynamicList, "ss_tcp_header_request_path", "%s - %s" % { translate("TCP"), translate("Header Request Path") })
o:depends("ss_tcp_header_type", "http")

o = s:option(DynamicList, "ss_tcp_header_request_headers", "%s - %s" % { translate("TCP"), translate("Header Request Headers") },
	translate("example: Host: example.com"))
o:depends("ss_tcp_header_type", "http")

o = s:option(Value, "ss_tcp_header_response_version", "%s - %s" % { translate("TCP"), translate("Header Response Version") })
o:depends("ss_tcp_header_type", "http")

o = s:option(Value, "ss_tcp_header_response_status", "%s - %s" % { translate("TCP"), translate("Header Response Status") })
o:depends("ss_tcp_header_type", "http")

o = s:option(Value, "ss_tcp_header_response_reason", "%s - %s" % { translate("TCP"), translate("Header Response Reason") })
o:depends("ss_tcp_header_type", "http")

o = s:option(DynamicList, "ss_tcp_header_response_headers", "%s - %s" % { translate("TCP"), translate("Header Response Headers") },
	translate("example: Host: example.com"))
o:depends("ss_tcp_header_type", "http")

-- StreamSettings - KCP
o = s:option(Value, "ss_kcp_mtu", "%s - %s" % { translate("KCP"), translate("MTU") })
o:depends("ss_network", "kcp")
o.datatype = "and(uinteger, min(576), max(1460))"

o = s:option(Value, "ss_kcp_tti", "%s - %s" % { translate("KCP"), translate("TTI") })
o:depends("ss_network", "kcp")
o.datatype = "and(uinteger, min(10), max(100))"

o = s:option(Value, "ss_kcp_uplinkcapacity", "%s - %s" % { translate("KCP"), translate("UplinkCapacity") })
o:depends("ss_network", "kcp")
o.datatype = "uinteger"

o = s:option(Value, "ss_kcp_downlinkcapacity", "%s - %s" % { translate("KCP"), translate("DownlinkCapacity") })
o:depends("ss_network", "kcp")
o.datatype = "uinteger"

o = s:option(Flag, "ss_kcp_congestion", "%s - %s" % { translate("KCP"), translate("Congestion") })
o:depends("ss_network", "kcp")

o = s:option(Value, "ss_kcp_readbuffersize", "%s - %s" % { translate("KCP"), translate("ReadBufferSize") })
o:depends("ss_network", "kcp")
o.datatype = "uinteger"

o = s:option(Value, "ss_kcp_writebuffersize", "%s - %s" % { translate("KCP"), translate("WriteBufferSize") })
o:depends("ss_network", "kcp")
o.datatype = "uinteger"

o = s:option(ListValue, "ss_kcp_header_type", "%s - %s" % { translate("KCP"), translate("Header Type") })
o:depends("ss_network", "kcp")
o:value("")
o:value("none", translate("None"))
o:value("srtp")
o:value("utp")
o:value("wechat-video")
o:value("dtls")
o:value("wireguard")

o = s:option(Value, "ss_kcp_seed", "%s - %s" % { translate("KCP"), translate("Seed") })
o:depends("ss_network", "kcp")

-- StreamSettings - WebSocket
o = s:option(Value, "ss_ws_path", "%s - %s" % { translate("WebSocket"), translate("Path") })
o:depends("ss_network", "ws")

o = s:option(DynamicList, "ss_ws_headers", "%s - %s" % { translate("WebSocket"), translate("Headers") },
	translate("example: Host: example.com"))
o:depends("ss_network", "ws")

-- StreamSettings - HTTP/2
o = s:option(DynamicList, "ss_http_host", "%s - %s" % { translate("HTTP/2"), translate("Host") },
	translate("example: example.com"))
o:depends("ss_network", "http")

o = s:option(Value, "ss_http_path", "%s - %s" % { translate("HTTP/2"), translate("Path") })
o:depends("ss_network", "http")

o = s:option(Value, "ss_http_readidletimeout", "%s - %s" % { translate("HTTP/2"), translate("ReadIdleTimeout") })
o:depends("ss_network", "http")
o.datatype = "uinteger"

o = s:option(Value, "ss_http_healthchecktimeout", "%s - %s" % { translate("HTTP/2"), translate("HealthCheckTimeout") })
o:depends("ss_network", "http")
o.datatype = "uinteger"

-- StreamSettings - DomainSocket

-- StreamSettings - QUIC
o = s:option(ListValue, "ss_quic_security", "%s - %s" % { translate("QUIC"), translate("Security") })
o:depends("ss_network", "quic")
o:value("")
o:value("none", translate("None"))
o:value("aes-128-gcm")
o:value("chacha20-poly1305")

o = s:option(Value, "ss_quic_key", "%s - %s" % { translate("QUIC"), translate("Key") },
	translate("just security isn't none"))
o:depends("ss_network", "quic")

o = s:option(ListValue, "ss_quic_header_type", "%s - %s" % { translate("QUIC"), translate("Header Type") })
o:depends("ss_network", "quic")
o:value("none", translate("None"))
o:value("srtp")
o:value("utp")
o:value("wechat-video")
o:value("dtls")
o:value("wireguard")

-- StreamSettins - GRPC
o = s:option(Value, "ss_grpc_servicename", "%s - %s" % { translate("GRPC"), translate("ServiceName") })
o:depends("ss_network", "grpc")

o = s:option(Flag, "ss_grpc_multimode", "%s - %s" % { translate("GRPC"), translate("MultiMode") })
o:depends("ss_network", "grpc")

o = s:option(Value, "ss_grpc_idletimeout", "%s - %s" % { translate("GRPC"), translate("IdleTimeout") })
o:depends("ss_network", "grpc")

o = s:option(Value, "ss_grpc_healthchecktimeout", "%s - %s" % { translate("GRPC"), translate("HealthCheckTimeout") })
o:depends("ss_network", "grpc")

o = s:option(Value, "ss_grpc_permitwithoutstream", "%s - %s" % { translate("GRPC"), translate("PermitWithoutStream") })
o:depends("ss_network", "grpc")

-- StreamSettings - Sockopt
o = s:option(Value, "ss_sockopt_mark", "%s - %s" % { translate("Sockopt"), translate("Mark") },
	translate("Mark Output"))
o.datatype = "and(uinteger, min(0), max(255))"

o = s:option(Value, "ss_sockopt_tcpfastopen", "%s - %s" % { translate("Sockopt"), translate("TCPFastOpen") })
o.datatype = "or(bool, integer)"

o = s:option(ListValue, "ss_sockopt_tproxy", "%s - %s" % { translate("Sockopt"), translate("TProxy") })
o:value("")
o:value("off")
o:value("redirect")
o:value("tproxy")

o = s:option(ListValue, "ss_sockopt_domainstrategy", "%s - %s" % { translate("Sockopt"), translate("DomainStrategy") })
o:value("")
o:value("AsIs")
o:value("UseIP")
o:value("UseIPv4")
o:value("UseIPv6")

o = s:option(Value, "ss_sockopt_dialerproxy", "%s - %s" % { translate("Sockopt"), translate("DialerProxy") })

o = s:option(Flag, "ss_sockopt_acceptproxyprotocol", "%s - %s" % { translate("Sockopt"), translate("AcceptProxyProtocol") })

return m