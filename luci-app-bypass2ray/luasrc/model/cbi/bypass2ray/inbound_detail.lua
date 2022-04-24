local dsp = require "luci.dispatcher"
local nixio = require "nixio"
local util = require "luci.util"
local appname = require "luci.model.cbi.bypass2ray.support".appname
local m, s, o

local uuid = arg[1]

m = Map(appname, "%s - %s" % { translate("ByPass2Ray"), translate("Edit Inbound") })
m.redirect = dsp.build_url("admin", "services", appname, "inbound")

if m.uci:get(appname, uuid) ~= "inbound" then
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

s = m:section(NamedSection, uuid, "inbound")
s.anonymous = true
s.addremove = false

o = s:option(Value, "alias", translate("Alias"))
o.rmempty = false

o = s:option(Flag, "enable", translate("Enable"))
o.default = false

o = s:option(Value, "listen", translate("Listen"))
for _, v in ipairs(allow_choose_listen_ips) do
	o:value(v)
end
o.datatype = "ipaddr"

o = s:option(Value, "port", translate("Port"))
o.rmempty = false
o.datatype = "or(port, portrange)"

o = s:option(ListValue, "protocol", translate("Protocol"))
o:value("dokodemo-door", "Dokodemo-door")
o:value("http", "HTTP")
o:value("shadowsocks", "Shadowsocks")
o:value("socks", "Socks")
o:value("vmess", "VMess")
o:value("trojan", "Trojan")
o:value("vless", "VLESS")

-- Dokodemo-door
o = s:option(Value, "settings_dokodemodoor_address", "%s - %s" % { "Dokodemo-door", translate("Address") },
	translate("Address of the destination server."))
o:depends("protocol", "dokodemo-door")
o.datatype = "host"

o = s:option(Value, "settings_dokodemodoor_port", "%s - %s" % { "Dokodemo-door", translate("Port") })
o:depends("protocol", "dokodemo-door")
o.datatype = "port"

o = s:option(MultiValue, "settings_dokodemodoor_network", "%s - %s" % { "Dokodemo-door", translate("Network") })
o:depends("protocol", "dokodemo-door")
o:value("tcp")
o:value("udp")

o = s:option(Value, "settings_dokodemodoor_timeout", "%s - %s" % { "Dokodemo-door", translate("Timeout") })
o:depends("protocol", "dokodemo-door")
o.datatype = "uinteger"
o.placeholder = "300"

o = s:option(Flag, "settings_dokodemodoor_followredirect", "%s - %s" % { "Dokodemo-door", translate("Follow Redirect") })
o:depends("protocol", "dokodemo-door")

-- Settings - HTTP
o = s:option(Value, "settings_http_account_user", "%s - %s" % { "HTTP", translate("Account User") })
o:depends("protocol", "http")

o = s:option(Value, "settings_http_account_pass", "%s - %s" % { "HTTP", translate("Account Password") })
o:depends("protocol", "http")
o.password = true

o = s:option(Flag, "settings_http_allowtransparent", "%s - %s" % { "HTTP", translate("Allow Transparent") })
o:depends("protocol", "http")

o = s:option(Value, "settings_http_timeout", "%s - %s" % { "HTTP", translate("Timeout") },
	translate("Time limit for inbound data(seconds)"))
o:depends("protocol", "http")
o.datatype = "uinteger"
o.placeholder = "300"

-- Settings - Shadowsocks
--o = s:option(Value, "settings_shadowsocks_email", "%s - %s" % { "Shadowsocks", translate("Email") })
--o:depends("protocol", "shadowsocks")

o = s:option(ListValue, "settings_shadowsocks_method", "%s - %s" % { "Shadowsocks", translate("Method") })
o:depends("protocol", "shadowsocks")
o:value("none")
o:value("aes-256-cfb")
o:value("aes-128-cfb")
o:value("chacha20")
o:value("chacha20-ietf")
o:value("aes-256-gcm")
o:value("aes-128-gcm")
o:value("chacha20-poly1305")
o:value("chacha20-ietf-poly1305")

o = s:option(Value, "settings_shadowsocks_password", "%s - %s" % { "Shadowsocks", translate("Password") })
o:depends("protocol", "shadowsocks")
o.password = true

--o = s:option(Value, "settings_shadowsocks_level", "%s - %s" % { "Shadowsocks", translate("User level") })
--o:depends("protocol", "shadowsocks")
--o.datatype = "uinteger"

--o = s:option(Flag, "settings_shadowsocks_ota", "%s - %s" % { "Shadowsocks", translate("One Time Auth (OTA)") })
--o:depends("protocol", "shadowsocks")

o = s:option(MultiValue, "settings_shadowsocks_network", "%s - %s" % { "Shadowsocks", translate("Network") })
o:depends("protocol", "shadowsocks")
o:value("")
o:value("tcp")
o:value("udp")

-- Settings - Socks
o = s:option(ListValue, "settings_socks_auth", "%s - %s" % { "Socks", translate("Auth") })
o:depends("protocol", "socks")
o:value("")
o:value("noauth", translate("No Auth"))
o:value("password", translate("Password"))

o = s:option(Value, "settings_socks_account_user", "%s - %s" % { "Socks", translate("Account User") })
o:depends("settings_socks_auth", "password")

o = s:option(Value, "settings_socks_account_pass", "%s - %s" % { "Socks", translate("Account Password") })
o:depends("settings_socks_auth", "password")
o.password = true

o = s:option(Flag, "settings_socks_udp", "%s - %s" % { "Socks", translate("UDP") })
o:depends("protocol", "socks")

o = s:option(Value, "settings_socks_ip", "%s - %s" % { "Socks", translate("IP") })
o:depends("settings_socks_udp", "1")
for _, v in ipairs(allow_choose_listen_ips) do
	o:value(v)
end
o.datatype = "host"
o.placeholder = "127.0.0.1"

--o = s:option(Value, "settings_socks_user_level", "%s - %s" % { "Socks", translate("User level") },
	--translate("All connections share this level"))
--o:depends("protocol", "socks")
--o.datatype = "uinteger"

-- Settings - VMess
o = s:option(Value, "settings_vmess_client_id", "%s - %s" % { "VMess", translate("Client ID") })
o:depends("protocol", "vmess")

o = s:option(Value, "settings_vmess_client_alterid", "%s - %s" % { "VMess", translate("Client Alter ID") })
o:depends("protocol", "vmess")
o.datatype = "and(uinteger, max(65535))"

--o = s:option(Value, "settings_vmess_client_email", "%s - %s" % { "VMess", translate("Client email") })
--o:depends("protocol", "vmess")

--o = s:option(Value, "settings_vmess_client_user_level", "%s - %s" % { "VMess", translate("Client User level") })
--o:depends("protocol", "vmess")
--o.datatype = "uinteger"

o = s:option(Value, "settings_vmess_default_alterid", "%s - %s" % { "VMess", translate("Default Alter ID") })
o:depends("protocol", "vmess")
o.datatype = "and(uinteger, max(65535))"

--o = s:option(Value, "settings_vmess_default_user_level", "%s - %s" % { "VMess", translate("Default user level") })
--o:depends("protocol", "vmess")
--o.datatype = "uinteger"

o = s:option(Value, "settings_vmess_detour_to", "%s - %s" % { "VMess", translate("Detour To") })
o:depends("protocol", "vmess")

o = s:option(Flag, "settings_vmess_disableinsecureencryption", "%s - %s" % { "VMess", translate("Disable Insecure Encryption") })
o:depends("protocol", "vmess")

-- Settings - Trojan
o = s:option(Value, "settings_trojan_password", "%s - %s" % { "Trojan", translate("Password") })
o:depends("protocol", "trojan")
o.password = true

o = s:option(ListValue, "settings_trojan_flow", "%s - %s" % { "Trojan", translate("Flow") })
o:depends("protocol", "trojan")
o:value("", translate("None"))
o:value("xtls-rprx-direct")
o:value("xtls-rprx-origin")
o:value("xtls-rprx-origin-udp443")

--[[
o = s:option(Value, "settings_trojan_fallback_name", "%s - %s" % { "Trojan", translate("Fallback Name") })
o:depends("protocol", "trojan")

o = s:option(Value, "settings_trojan_fallback_alpn", "%s - %s" % { "Trojan", translate("Fallback ALPN") })
o:depends("protocol", "trojan")

o = s:option(Value, "settings_trojan_fallback_path", "%s - %s" % { "Trojan", translate("Fallback Path") })
o:depends("protocol", "trojan")

o = s:option(Value, "settings_trojan_fallback_dest", "%s - %s" % { "Trojan", translate("Fallback Dest") })
o:depends("protocol", "trojan")

o = s:option(ListValue, "settings_trojan_fallback_xver", "%s - %s" % { "Trojan", translate("Fallback Xver") })
o:depends("protocol", "trojan")
o:value("0")
o:value("1")
o:value("2")
o.default = "0"
--]]

-- Settings - VLESS
o = s:option(Value, "settings_vless_id", "%s - %s" % { "VLESS", translate("ID") })
o:depends("protocol", "vless")

o = s:option(ListValue, "settings_vless_flow", "%s - %s" % { "VLESS", translate("Flow") })
o:depends("protocol", "vless")
o:value("", translate("None"))
o:value("xtls-rprx-direct")
o:value("xtls-rprx-origin")
o:value("xtls-rprx-origin-udp443")

o = s:option(ListValue, "settings_vless_decryption", "%s - %s" % { "VLESS", translate("Decryption") })
o:depends("protocol", "vless")
o:value("none", translate("None"))

-- Settings - VLESS Fallback
--[[

o = s:option(Value, "settings_vless_fallback_name", "%s - %s" % { "VLESS", translate("Fallback Name") })
o:depends("protocol", "vless")

o = s:option(Value, "settings_vless_fallback_alpn", "%s - %s" % { "VLESS", translate("Fallback ALPN") })
o:depends("protocol", "vless")

o = s:option(Value, "settings_vless_fallback_path", "%s - %s" % { "VLESS", translate("Fallback Path") })
o:depends("protocol", "vless")

o = s:option(Value, "settings_vless_fallback_dest", "%s - %s" % { "VLESS", translate("Fallback Dest") })
o:depends("protocol", "vless")

o = s:option(ListValue, "settings_vless_fallback_xver", "%s - %s" % { "VLESS", translate("Fallback Xver") })
o:depends("protocol", "vless")
o:value("0")
o:value("1")
o:value("2")
o.default = "0"
--]]

-- Settings - VLESS Fallback
--[[
o = s:section(Value, "settings_vless_fallback_name", "%s - %s" % { "VLESS", translate("Fallback Name") })
o:depends("protocol", "vless")

o = s:section(Value, "settings_vless_fallback_alpn", "%s - %s" % { "VLESS", translate("Fallback ALPN") })
o:depends("protocol", "vless")

o = s:section(Value, "settings_vless_fallback_path", "%s - %s" % { "VLESS", translate("Fallback Path") })
o:depends("protocol", "vless")

o = s:section(Value, "settings_vless_fallback_dest", "%s - %s" % { "VLESS", translate("Fallback Dest") })
o:depends("protocol", "vless")

o = s:section(ListValue, "settings_vless_fallback_xver", "%s - %s" % { "VLESS", translate("Fallback Xver") })
o:depends("protocol", "vless")
o:value("0")
o:value("1")
o:value("2")
o.default = "0"
--]]

-- Stream Settings
o = s:option(ListValue, "ss_network", "%s - %s" % { "Stream Settings", translate("Network") })
o:value("")
o:value("tcp", "TCP")
o:value("kcp", "mKCP")
o:value("ws", "WebSocket")
o:value("http", "HTTP/2")
o:value("domainsocket", "Domain Socket")
o:value("quic", "QUIC")
o:value("grpc", "GRPC")

o = s:option(ListValue, "ss_security", "%s - %s" % { "Stream Settings", translate("Security") })
o:value("")
o:value("none", translate("None"))
o:value("tls", "(X)TLS")

-- Stream Settings - (X)TLS
o = s:option(Value, "ss_tls_servername", "%s - %s" % { "(X)TLS", translate("Server Name") })
o:depends("ss_security", "tls")
o.datatype = "host"

o = s:option(Flag, "ss_tls_rejectunknownsni", "%s - %s" % { "(X)TLS", translate("Reject Unknown SNI") })
o:depends("ss_security", "tls")

o = s:option(MultiValue, "ss_tls_alpn", "%s - %s" % { "(X)TLS", "ALPN" })
o:depends("ss_security", "tls")
o:value("h2")
o:value("http/1.1")

o = s:option(ListValue, "ss_tls_minversion", "%s - %s" % { "(X)TLS", "Min Version" })
o:depends("ss_security", "tls")
o:value("")
o:value("1.1")
o:value("1.2")
o:value("1.3")

o = s:option(ListValue, "ss_tls_maxversion", "%s - %s" % { "(X)TLS", "Max Version" })
o:depends("ss_security", "tls")
o:value("")
o:value("1.1")
o:value("1.2")
o:value("1.3")

o = s:option(Flag, "ss_tls_allowinsecure", "%s - %s" % { "(X)TLS", translate("Allow Insecure") })
o:depends("ss_security", "tls")

o = s:option(DynamicList, "ss_tls_ciphersuites", "%s - %s" % { "(X)TLS", translate("Cipher Suites") })
o:depends("ss_security", "tls")

o = s:option(Flag, "ss_tls_disablesystemroot", "%s - %s" % { "(X)TLS", translate("Disable System Root") })
o:depends("ss_security", "tls")

o = s:option(Flag, "ss_tls_enablesessionresumption", "%s - %s" % { "(X)TLS", translate("Enable Session Resumption") })
o:depends("ss_security", "tls")

o = s:option(ListValue, "ss_tls_fingerprint", "%s - %s" % { "(X)TLS", translate("TLS Client Hello") })
o:depends("ss_security", "tls")
o:value("")
o:value("chrome")
o:value("firefox")
o:value("safari")
o:value("randomized")

o = s:option(Value, "ss_tls_certificates_ocspstapling", "%s - %s" % { "(X)TLS Certificate", translate("OCSP Stapling") })
o:depends("ss_security", "tls")
o.datatype = "uinteger"
--o.default = "3600"

o = s:option(Flag, "ss_tls_certificates_onetimeloading", "%s - %s" % { "(X)TLS Certificate", translate("OneTimeLoading") })
o:depends("ss_security", "tls")

o = s:option(ListValue, "ss_tls_certificates_usage", "%s - %s" % { "(X)TLS Certificate", translate("Usage") })
o:depends("ss_security", "tls")
o:value("")
o:value("encipherment")
o:value("verify")
o:value("issue")

o = s:option(Value, "ss_tls_certificates_certificatefile", "%s - %s" % { "(X)TLS Certificate", translate("Certificate File") })
o:depends("ss_security", "tls")

o = s:option(Value, "ss_tls_certificates_keyfile", "%s - %s" % { "(X)TLS Certificate", translate("Key File") })
o:depends("ss_security", "tls")

-- Stream Settings - TCP
o = s:option(Flag, "ss_tcp_acceptproxyprotocol", "%s - %s" % { "TCP", translate("Accept Proxy Protocol") })
o:depends("ss_network", "tcp")

o = s:option(ListValue, "ss_tcp_header_type", "%s - %s" % { "TCP", translate("Header Type") })
o:depends("ss_network", "tcp")
o:value("")
o:value("none", translate("None"))
o:value("http", "HTTP")

o = s:option(Value, "ss_tcp_header_request_version", "%s - %s" % { "TCP", translate("Request Version") })
o:depends("ss_tcp_header_type", "http")
--o.placeholder = "1.1"

o = s:option(ListValue, "ss_tcp_header_request_method", "%s - %s" % { "TCP", translate("Request Method") })
o:depends("ss_tcp_header_type", "http")
o:value("")
o:value("GET")
o:value("HEAD")
o:value("POST")
o:value("DELETE")
o:value("PUT")
o:value("PATCH")
o:value("OPTIONS")

o = s:option(DynamicList, "ss_tcp_header_request_path", "%s - %s" % { "TCP", translate("Request Path") })
o:depends("ss_tcp_header_type", "http")
--o.default = "/"

o = s:option(DynamicList, "ss_tcp_header_request_headers", "%s - %s" % { "TCP", translate("Request Headers") },
	translate("example: Host:example.com"))
o:depends("ss_tcp_header_type", "http")

o = s:option(Value, "ss_tcp_header_response_version", "%s - %s" % { "TCP", translate("Response Version") })
o:depends("ss_tcp_header_type", "http")
--o.placeholder = "1.1"

o = s:option(Value, "ss_tcp_header_response_status", "%s - %s" % { "TCP", translate("Response Status") })
o:depends("ss_tcp_header_type", "http")
--o.placeholder = "200"

o = s:option(Value, "ss_tcp_header_response_reason", "%s - %s" % { "TCP", translate("Response Reason") })
o:depends("ss_tcp_header_type", "http")
--o.placeholder = "OK"

o = s:option(DynamicList, "ss_tcp_header_response_headers", "%s - %s" % { "TCP", translate("Response Headers") },
	translate("example: Host:example.com"))
o:depends("ss_tcp_header_type", "http")

-- Stream Settings - KCP
o = s:option(Value, "ss_kcp_mtu", "%s - %s" % { "KCP", translate("MTU") })
o:depends("ss_network", "kcp")
o.datatype = "and(min(576), max(1460))"
o.placeholder = "1350"

o = s:option(Value, "ss_kcp_tti", "%s - %s" % { "KCP", translate("TTI") })
o:depends("ss_network", "kcp")
o.datatype = "and(min(10), max(100))"
o.placeholder = "50"

o = s:option(Value, "ss_kcp_uplinkcapacity", "%s - %s" % { "KCP", translate("Uplink Capacity") })
o:depends("ss_network", "kcp")
o.datatype = "uinteger"
o.placeholder = "5"

o = s:option(Value, "ss_kcp_downlinkcapacity", "%s - %s" % { "KCP", translate("Downlink Capacity") })
o:depends("ss_network", "kcp")
o.datatype = "uinteger"
o.placeholder = "20"

o = s:option(Flag, "ss_kcp_congestion", "%s - %s" % { "KCP", translate("Congestion Enabled") })
o:depends("ss_network", "kcp")

o = s:option(Value, "ss_kcp_readbuffersize", "%s - %s" % { "KCP", translate("Read Buffer Size") })
o:depends("ss_network", "kcp")
o.datatype = "uinteger"
o.placeholder = "2"

o = s:option(Value, "ss_kcp_writebuffersize", "%s - %s" % { "KCP", translate("Write Buffer Size") })
o:depends("ss_network", "kcp")
o.datatype = "uinteger"
o.placeholder = "2"

o = s:option(ListValue, "ss_kcp_header_type", "%s - %s" % { "KCP", translate("Header Type") })
o:depends("ss_network", "kcp")
o:value("")
o:value("none", translate("None"))
o:value("srtp", "SRTP")
o:value("utp", "uTP")
o:value("wechat-video", translate("Wechat Video"))
o:value("dtls", "DTLS 1.2")
o:value("wireguard", "WireGuard")

o = s:option(Value, "ss_kcp_seed", "%s - %s" % { "KCP", translate("Seed") })
o:depends("ss_network", "kcp")

-- Stream Settings - WebSocket
o = s:option(Flag, "ss_ws_acceptproxyprotocol", "%s - %s" % { "WebSocket", translate("Accept Proxy Protocol") })
o:depends("ss_network", "ws")

o = s:option(Value, "ss_ws_path", "%s - %s" % { "WebSocket", translate("Path") })
o:depends("ss_network", "ws")

o = s:option(DynamicList, "ss_ws_headers", "%s - %s" % { "WebSocket", translate("Headers") },
	translate("example: Host:example.com"))
o:depends("ss_network", "ws")

-- Stream Settings - HTTP/2
o = s:option(DynamicList, "ss_http_host", "%s - %s" % { "HTTP/2", translate("Host") })
o:depends("ss_network", "http")

o = s:option(Value, "ss_http_path", "%s - %s" % { "HTTP/2", translate("Path") })
o:depends("ss_network", "http")
--o.placeholder = "/"

o = s:option(Value, "ss_http_readidletimeout", "%s - %s" % { "HTTP/2", translate("Read Idle Timeout") })
o:depends("ss_network", "http")
o.datatype = "uinteger"

o = s:option(Value, "ss_http_healthchecktimeout", "%s - %s" % { "HTTP/2", translate("Health Check Timeout") })
o:depends("ss_network", "http")
o.datatype = "uinteger"

-- Stream Settings - Domain Socket
o = s:option(Value, "ss_domainsocket_path", "%s - %s" % { "Domain Socket", translate("Path") })
o:depends("ss_network", "domainsocket")

-- Stream Settings - QUIC
o = s:option(ListValue, "ss_quic_security", "%s - %s" % { "QUIC", translate("Security") })
o:depends("ss_network", "quic")
o:value("")
o:value("none", translate("None"))
o:value("aes-128-gcm")
o:value("chacha20-poly1305")

o = s:option(Value, "ss_quic_key", "%s - %s" % { "QUIC", translate("Key") })
o:depends("ss_quic_security", "aes-128-gcm")
o:depends("ss_quic_security", "chacha20-poly1305")

o = s:option(ListValue, "ss_quic_header_type", "%s - %s" % { "QUIC", translate("Header Type") })
o:depends("ss_network", "quic")
o:value("")
o:value("none", translate("None"))
o:value("srtp", "SRTP")
o:value("utp", "uTP")
o:value("wechat-video", translate("Wechat Video"))
o:value("dtls", "DTLS 1.2")
o:value("wireguard", "WireGuard")

-- Stream Settings - GRPC
o = s:option(ListValue, "ss_grpc_servicename", "%s - %s" % { "GRPC", translate("Service Name") })
o:depends("ss_network", "grpc")

o = s:option(Flag, "ss_grpc_multimode", "%s - %s" % { "GRPC", translate("Multi Mode") })
o:depends("ss_network", "grpc")

o = s:option(Value, "ss_grpc_idletimeout", "%s - %s" % { "GRPC", translate("Idle Timeout") })
o:depends("ss_network", "grpc")
--o.default = "10"

o = s:option(Value, "ss_grpc_healthchecktimeout", "%s - %s" % { "GRPC", translate("Health Check Timeout") })
o:depends("ss_network", "grpc")
--o.default = "20"

o = s:option(Value, "ss_grpc_permitwithoutstream", "%s - %s" % { "GRPC", translate("Permit Without Stream") })
o:depends("ss_network", "grpc")

-- Stream Settings - Socket Options
o = s:option(Value, "ss_sockopt_tcpfastopen", "%s - %s" % { "Sockopt", translate("TCP Fast Open") })
o.datatype = "or(bool, uinteger)"

o = s:option(ListValue, "ss_sockopt_tproxy", "%s - %s" % { "Sockopt", translate("TProxy") },
	translate("If transparent proxy enabled on current inbound, this option will be ignored."))
o:value("")
o:value("redirect", "Redirect")
o:value("tproxy", "TProxy")
o:value("off", translate("Off"))

o = s:option(ListValue, "ss_sockopt_domainstrategy", "%s - %s" % { "Sockopt", translate("DomainStrategy") })
o:value("", translate("None"))
o:value("AsIs")
o:value("UseIP")
o:value("UseIPv4")
o:value("UseIPv6")

o = s:option(Value, "ss_sockopt_dialerproxy", "%s - %s" % { "Sockopt", translate("Dialer Proxy") })

o = s:option(Flag, "ss_sockopt_acceptproxyprotocol", "%s - %s" % { "Sockopt", translate("Accept Proxy Protocol") })

-- Other Settings
o = s:option(Value, "tag", translate("Tag"))

o = s:option(Flag, "sniffing_enabled", "%s - %s" %{ "Sniffing", translate("Enabled") })

o = s:option(MultiValue, "sniffing_destoverride", "%s - %s" % { "Sniffing", translate("Dest Override") })
o:value("http")
o:value("tls")
o:value("fakedns")

o = s:option(Flag, "sniffing_metadataonly", "%s - %s" %{ "Sniffing", translate("Metadata Only") },
	translate("仅使用连接的元数据嗅探目标地址"))

o = s:option(Flag, "sniffing_routeonly", "%s - %s" %{ "Sniffing", translate("Route Only") })

o = s:option(DynamicList, "sniffing_domainsexcluded", "%s - %s" %{ "Sniffing", translate("Domains Excluded") })

o = s:option(ListValue, "allocate_strategy", "%s - %s" % { "Allocate", translate("Strategy") })
o:value("")
o:value("always")
o:value("random")

o = s:option(Value, "allocate_refresh", "%s - %s" % { "Allocate", translate("Refresh") })
o.datatype = "uinteger"

o = s:option(Value, "allocate_concurrency", "%s - %s" % { "Allocate", translate("Concurrency") })
o.datatype = "uinteger"

return m