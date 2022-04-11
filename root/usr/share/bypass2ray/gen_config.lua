#!/usr/bin/lua
local uci = require 'luci.model.uci'
local jsonc = require 'luci.jsonc'

local gen_config_name = arg[1]
local gen_config_file = arg[2]

if not gen_config_file or not gen_config_name then
    return 1
end

local appname = gen_config_name

function GetInboundAll()
    local tablePre = {}
    uci:foreach(appname, "inbound", function(s)
        table.insert(tablePre, s)
    end)
    return tablePre
end

function GetOutboundAll()
    local tablePre = {}
    uci:foreach(appname, "outbound", function(s)
        table.insert(tablePre, s)
    end)
    return tablePre
end

function GetRoutingGlobal()
    local tablePre = {}
    uci:foreach(appname, "routing_global_settings", function(s)
        table.insert(tablePre, s)
    end)
    return tablePre
end

function GetRoutingRule()
    local tablePre = {}
    uci:foreach(appname, "routing_rule", function(s)
        table.insert(tablePre, s)
    end)
    return tablePre
end

function GetRoutingBalancer()
    local tablePre = {}
    uci:foreach(appname, "routing_balancer", function(s)
        table.insert(tablePre, s)
    end)
    return tablePre
end

function GetGlobal()
    local tablePre = {}
    uci:foreach(appname, "global", function(s)
        table.insert(tablePre, s)
    end)
    return tablePre
end

---
local inbounds = {}
local outbounds = {}
local routing = {}
local log = {}
local dns = {}

--- Support
function split(str, d)
	local lst = { }
	local n = string.len(str)
	local start = 1
	while start <= n do
		local i = string.find(str, d, start) -- find 'next' 0
		if i == nil then 
			table.insert(lst, string.sub(str, start, n))
			break 
		end
		table.insert(lst, string.sub(str, start, i-1))
		if i == n then
			table.insert(lst, "")
			break
		end
		start = i + 1
	end
	return lst
end

function ListToMap(s)
    local TempMap = {}
    for _, value in ipairs(s) do
        local t = split(value, "=")
        TempMap[t[1]] = t[2]
    end
    return TempMap
end

---
local InboundCfg = GetInboundAll()
local OutboundCfg = GetOutboundAll()
local RoutingGlobalCfg = GetRoutingGlobal()
local RoutingRuleCfg = GetRoutingRule()
local RoutingBalancerCfg = GetRoutingBalancer()
local LogCfg = GetGlobal()

local routing_rule = {}
local routing_balancer = {}

for _, v in ipairs(InboundCfg) do
    if v["enable"] then
        local TempTable = {}
        if v["alias"] then
            TempTable["alias"] = v["alias"]
        end
        -- Tag
        if v["tag"] then
            TempTable["tag"] = v["tag"]
        end
        -- Listen
        if v["listen"] then
            TempTable["listen"] = v["listen"]
        end
        -- Port
        if v["port"] then
            TempTable["port"] = tonumber(v["port"])
        end
        -- Protocol
        if v["protocol"] then
            TempTable["protocol"] = v["protocol"]
        end
        ---
        local xtls = false
        ---
        -- Protocol Switch
        if v["protocol"] == "dokodemo-door" then
            local settings = {}
            if v["settings_dokodemodoor_address"] then
                settings["address"] = v["settings_dokodemodoor_address"]
            end
            if v["settings_dokodemodoor_port"] then
                settings["port"] = tonumber(v["settings_dokodemodoor_port"])
            end
            if v["settings_dokodemodoor_network"] then
                settings["network"] = table.concat(split(v["settings_dokodemodoor_network"], " "), ",")
            end
            if v["settings_dokodemodoor_timeout"] then
                settings["timeout"] = tonumber(v["settings_dokodemodoor_timeout"])
            end
            if v["settings_dokodemodoor_followredirect"] then
                settings["followRedirect"] = true
            end
            TempTable["settings"] = settings
        elseif v["protocol"] == "http" then
            local settings = {}
            if v["settings_http_account_user"] then
                if not settings["accounts"] then
                    settings["accounts"] = {}
                end
                settings["accounts"]["user"] = v["settings_http_account_user"]
            end
            if v["settings_http_account_pass"] then
                if not settings["accounts"] then
                    settings["accounts"] = {}
                end
                settings["accounts"]["pass"] = v["settings_http_account_pass"]
            end
            if v["settings_http_timeout"] then
                settings["timeout"] = tonumber(v["settings_http_timeout"])
            end
            if v["settings_http_allowtransparent"] then
                settings["allowTransparent"] = true
            end
            TempTable["settings"] = settings
        elseif v["protocol"] == "shadowsocks" then
            local settings = {}
            if v["settings_shadowsocks_method"] then
                if not settings["clients"] then
                    settings["clients"] = {}
                end
                settings["clients"]["method"] = v["settings_shadowsocks_method"]
            end
            if v["settings_shadowsocks_password"] then
                if not settings["clients"] then
                    settings["clients"] = {}
                end
                settings["clients"]["password"] = v["settings_shadowsocks_password"]
            end
            if v["settings_shadowsocks_network"] then
                settings["network"] = table.concat(split(v["settings_shadowsocks_network"], " "), ",")
            end
            TempTable["settings"] = settings
        elseif v["protocol"] == "socks" then
            local settings = {}
            if v["settings_socks_auth"] then
                settings["auth"] = v["settings_socks_auth"]
            end
            if v["settings_socks_account_user"] then
                if not settings["accounts"] then
                    settings["accounts"] = {}
                end
                settings["accounts"]["user"] = v["settings_socks_account_user"]
            end
            if v["settings_socks_account_pass"] then
                if not settings["accounts"] then
                    settings["accounts"] = {}
                end
                settings["accounts"]["pass"] = v["settings_socks_account_pass"]
            end
            if v["settings_socks_udp"] then
                settings["udp"] = true
            end
            if v["settings_socks_ip"] then
                settings["ip"] = v["settings_socks_ip"]
            end
            TempTable["settings"] = settings
        elseif v["protocol"] == "vmess" then
            local settings = {}
            if v["settings_vmess_client_id"] then
                if not settings["clients"] then
                    settings["clients"] = {}
                end
                settings["clients"]["id"] = v["settings_vmess_client_id"]
            end
            if v["settings_vmess_client_alterid"] then
                if not settings["clients"] then
                    settings["clients"] = {}
                end
                settings["clients"]["alterId"] = tonumber(v["settings_vmess_client_alterid"])
            end
            if v["settings_vmess_default_alterid"] then
                if not settings["default"] then
                    settings["default"] = {}
                end
                settings["default"]["alterId"] = tonumber(v["settings_vmess_default_alterid"])
            end
            if v["settings_vmess_detour_to"] then
                if not settings["detour"] then
                    settings["detour"] = {}
                end
                settings["detour"]["to"] = v["settings_vmess_detour_to"]
            end
            if v["settings_vmess_disableinsecureencryption"] then
                settings["disableInsecureEncryption"] = true
            end
            TempTable["settings"] = settings
        elseif v["protocol"] == "trojan" then
            local settings = {}
            if v["settings_trojan_password"] then
                if not settings["clients"] then
                    settings["clients"] = {}
                end
                settings["clients"]["password"] = v["settings_trojan_password"]
            end
            if v["settings_trojan_flow"] then
                if not settings["clients"] then
                    settings["clients"] = {}
                end
                settings["clients"]["flow"] = v["settings_trojan_flow"]
                xtls = true
            end
            TempTable["settings"] = settings
        elseif v["protocol"] == "vless" then
            local settings = {}
            if v["settings_vless_id"] then
                if not settings["clients"] then
                    settings["clients"] = {}
                end
                settings["clients"]["id"] = v["settings_vless_id"]
            end
            if v["settings_vless_flow"] then
                if not settings["clients"] then
                    settings["clients"] = {}
                end
                settings["clients"]["flow"] = v["settings_vless_flow"]
                xtls = true
            end
            TempTable["settings"] = settings
        end
        TempTable["streamSettings"] = {}
        if v["ss_network"] then
            TempTable["streamSettings"]["network"] = v["ss_network"]
        end
        if v["ss_security"] then
            if xtls then
                TempTable["streamSettings"]["security"] = "x" .. v["ss_security"]
            else
                TempTable["streamSettings"]["security"] = v["ss_security"]
            end
            local tls = {}
            if v["ss_tls_servername"] then
                tls["serverName"] = v["ss_tls_servername"]
            end
            if v["ss_tls_rejectunknownsni"] then
                tls["rejectUnknownSni"] = true
            end
            if v["ss_tls_alpn"] then
                tls["alpn"] = split(v["ss_tls_alpn"], " ")
            end
            if v["ss_tls_allowinsecure"] then
                tls["allowInsecure"] = true
            end
            if v["ss_tls_minversion"] then
                tls["minVersion"] = v["ss_tls_minversion"]
            end
            if v["ss_tls_maxversion"] then
                tls["maxVersion"] = v["ss_tls_maxversion"]
            end
            if v["ss_tls_ciphersuites"] then
                tls["cipherSuites"] = split(v["ss_tls_ciphersuites"], " ")
            end
            if v["ss_tls_disablesystemroot"] then
                tls["disableSystemRoot"] = true
            end
            if v["ss_tls_enablesessionresumption"] then
                tls["enableSessionResumption"] = true
            end
            if v["ss_tls_fingerprint"] then
                tls["fingerprint"] = v["ss_tls_fingerprint"]
            end
            local certificates = {}
            if v["ss_tls_certificates_onetimeloading"] then
                certificates["ocspStapling"] = tonumber(v["ss_tls_certificates_onetimeloading"])
            end
            if v["ss_tls_certificates_onetimeloading"] then
                certificates["oneTimeLoading"] = true
            end
            if v["ss_tls_certificates_usage"] then
                certificates["usage"] = v["ss_tls_certificates_usage"]
            end
            if v["ss_tls_certificates_certificatefile"] then
                certificates["certificateFile"] = v["ss_tls_certificates_certificatefile"]
            end
            if v["ss_tls_certificates_keyfile"] then
                certificates["keyFile"] = v["ss_tls_certificates_keyfile"]
            end
            if next(certificates) ~= nil then
                tls["certificates"] = {}
                table.insert(tls["certificates"], certificates)
            end
            if xtls then
                TempTable["streamSettings"]["xtlsSettings"] = tls
            else
                TempTable["streamSettings"]["tlsSettings"] = tls
            end
        end
        if v["ss_network"] == "tcp" then
            local settings = {}
            if v["ss_tcp_acceptproxyprotocol"] then
                settings["acceptProxyProtocol"] = true
            end
            if v["ss_tcp_header_type"] == "http" then
                settings["header"] = {}
                settings["header"]["type"] = "http"
                local request = {}
                if v["ss_tcp_header_request_version"] then
                    request["version"] = v["ss_tcp_header_request_version"]
                end
                if v["ss_tcp_header_request_method"] then
                    request["method"] = v["ss_tcp_header_request_method"]
                end
                if v["ss_tcp_header_request_path"] then
                    request["path"] = v["ss_tcp_header_request_path"]
                end
                if v["ss_tcp_header_request_headers"] then
                    request["headers"] = ListToMap(v["ss_tcp_header_request_headers"])
                end
                if next(request) ~= nil then
                    settings["header"]["request"] = request
                end
                local response = {}
                if v["ss_tcp_header_response_version"] then
                    response["version"] = v["ss_tcp_header_response_version"]
                end
                if v["ss_tcp_header_response_status"] then
                    response["status"] = v["ss_tcp_header_response_status"]
                end
                if v["ss_tcp_header_response_reason"] then
                    response["reason"] = v["ss_tcp_header_response_reason"]
                end
                if v["ss_tcp_header_response_headers"] then
                    response["headers"] = ListToMap(v["ss_tcp_header_response_headers"])
                end
                if next(response) ~= nil then
                    settings["header"]["response"] = response
                end
            end
            if next(settings) ~= nil then
                TempTable["streamSettings"]["tcpSettings"] = settings
            end
        elseif v["ss_network"] == "kcp" then
            local settings = {}
            if v["ss_kcp_mtu"] then
                settings["mtu"] = tonumber(v["ss_kcp_mtu"])
            end
            if v["ss_kcp_tti"] then
                settings["tti"] = tonumber(v["ss_kcp_tti"])
            end
            if v["ss_kcp_uplinkcapacity"] then
                settings["uplinkCapacity"] = tonumber(v["ss_kcp_uplinkcapacity"])
            end
            if v["ss_kcp_downlinkcapacity"] then
                settings["downlinkCapacity"] = tonumber(v["ss_kcp_downlinkcapacity"])
            end
            if v["ss_kcp_congestion"] then
                settings["congestion"] = true
            end
            if v["ss_kcp_readbuffersize"] then
                settings["readBufferSize"] = tonumber(v["ss_kcp_readbuffersize"])
            end
            if v["ss_kcp_writebuffersize"] then
                settings["writeBufferSize"] = tonumber(v["ss_kcp_writebuffersize"])
            end
            if v["ss_kcp_header_type"] and v["ss_kcp_header_type"] ~= "none" then
                settings["header"] = {}
                settings["header"]["type"] = v["ss_kcp_header_type"]
            end
            if v["ss_kcp_seed"] then
                settings["seed"] = v["ss_kcp_seed"]
            end
            if next(settings) ~= nil then
                TempTable["streamSettings"]["kcpSettings"] = settings
            end
        elseif v["ss_network"] == "ws" then
            local settings = {}
            if v["ss_ws_acceptproxyprotocol"] then
                settings["acceptProxyProtocol"] = true
            end
            if v["ss_ws_path"] then
                settings["path"] = v["ss_ws_path"]
            end
            if v["ss_ws_headers"] then
                settings["headers"] = ListToMap(v["ss_ws_headers"])
            end
            if next(settings) ~= nil then
                TempTable["streamSettings"]["wsSettings"] = settings
            end
        elseif v["ss_network"] == "http" then
            local settings = {}
            if v["ss_http_host"] then
                settings["host"] = v["ss_http_host"]
            end
            if v["ss_http_path"] then
                settings["path"] = v["ss_http_path"]
            end
            if v["ss_http_readidletimeout"] then
                settings["read_idle_timeout"] = tonumber(v["ss_http_readidletimeout"])
            end
            if v["ss_http_healthchecktimeout"] then
                settings["health_check_timeout"] = tonumber(v["ss_http_healthchecktimeout"])
            end
            if next(settings) ~= nil then
                TempTable["streamSettings"]["httpSettings"] = settings
            end
        elseif v["ss_network"] == "domainsocket" then
            local settings = {}
            if v["ss_domainsocket_path"] then
                settings["path"] = v["ss_domainsocket_path"]
            end
            if next(settings) ~= nil then
                TempTable["streamSettings"]["dsSettings"] = settings
            end
        elseif v["ss_network"] == "quic" then
            local settings = {}
            if v["ss_quic_security"] then
                settings["security"] = v["ss_quic_security"]
                if v["ss_quic_security"] ~= nil and v["ss_quic_security"] ~= "" and v["ss_quic_security"] ~= "none" then
                    if v["ss_quic_key"] then
                        settings["key"] = v["ss_quic_key"]
                    end
                end
            end
            if v["ss_quic_header_type"] and v["ss_quic_header_type"] ~= "none" and v["ss_quic_header_type"] ~= "" then
                settings["header"] = {}
                settings["header"]["type"] = v["ss_quic_header_type"]
            end
            if next(settings) ~= nil then
                TempTable["streamSettings"]["quicSettings"] = settings
            end
        elseif v["ss_network"] == "grpc" then
            local settings = {}
            if v["ss_grpc_servicename"] then
                settings["serviceName"] = v["ss_grpc_servicename"]
            end
            if v["ss_grpc_multimode"] then
                settings["multiMode"] = true
            end
            if v["ss_grpc_idletimeout"] then
               settings["idle_timeout"]  = tonumber(v["ss_grpc_idletimeout"])
            end
            if v["ss_grpc_healthchecktimeout"] then
                settings["health_check_timeout"]  = tonumber(v["ss_grpc_healthchecktimeout"])
            end
            if v["ss_grpc_permitwithoutstream"] then
                settings["permit_without_stream"] = true
            end
            if next(settings) ~= nil then
                TempTable["streamSettings"]["grpcSettings"] = settings
            end
        end
        local sockopt = {}
        if v["ss_sockopt_tcpfastopen"] then
            if v["ss_sockopt_tcp_fast_open"] == "true" then
                sockopt["tcpFastOpen"] = true
            elseif v["ss_sockopt_tcpfastopen"] ~= "false" then
                sockopt["tcpFastOpen"] = tonumber(v["ss_sockopt_tcpfastopen"])
            end
        end
        if v["ss_sockopt_tproxy"] then
            sockopt["tproxy"] = v["ss_sockopt_tproxy"]
        end
        if v["ss_sockopt_domainstrategy"] then
            sockopt["domainStrategy"] = v["ss_sockopt_domainstrategy"]
        end
        if v["ss_sockopt_dialerproxy"] then
            sockopt["dialerProxy"] = v["ss_sockopt_dialerproxy"]
        end
        if v["ss_sockopt_acceptproxyprotocol"] then
            sockopt["acceptProxyProtocol"] = true
        end
        if next(sockopt) ~= nil then
            TempTable["streamSettings"]["sockopt"] = sockopt
        end
        local sniffing = {}
        if v["sniffing_enabled"] then
            sniffing["enabled"] = true
        end
        if v["sniffing_destoverride"] then
            sniffing["destOverride"] = split(v["sniffing_destoverride"], " ")
        end
        if v["sniffing_metadataonly"] then
            sniffing["metadataOnly"] = true
        end
        if v["sniffing_routeonly"] then
            sniffing["routeOnly"] = true
        end
        if v["sniffing_domainsexcluded"] then
            sniffing["domainsExcluded"] = v["sniffing_domainsexcluded"]
        end
        if next(sniffing) ~= nil then
            TempTable["sniffing"] = sniffing
        end
        local allocate = {}
        if v["allocate_strategy"] then
            allocate["strategy"] = v["allocate_strategy"]
        end
        if v["allocate_refresh"] then
            allocate["refresh"] = tonumber(v["allocate_refresh"])
        end
        if v["allocate_concurrency"] then
            allocate["concurrency"] = tonumber(v["allocate_concurrency"])
        end
        if next(allocate) ~= nil then
            TempTable["allocate"] = allocate
        end
        table.insert(inbounds, TempTable)
    end
end

for _, v in ipairs(OutboundCfg) do
    if v["enable"] then
        local TempTable = {}
        if v["tag"] then
            TempTable["tag"] = v["tag"]
        end
        if v["alias"] then
            TempTable["alias"] = v["alias"]
        end
        if v["sendthrough"] then
            TempTable["sendthrough"] = v["sendthrough"]
        end
        local xtls = false
        if v["protocol"] then
            TempTable["protocol"] = v["protocol"]
            local settings = {}
            if v["protocol"] == "blackhole" then
                if v["settings_blackhole_response_type"] and v["settings_blackhole_response_type"] ~= "" and v["settings_blackhole_response_type"] ~= "none" then
                    settings["response"] = {}
                    settings["response"]["type"] = v["settings_blackhole_response_type"]
                end
            elseif v["protocol"] == "freedom" then
                if v["settings_freedom_domainstrategy"] then
                    settings["domainStrategy"] = v["settings_freedom_domainstrategy"]
                end
                if v["settings_freedom_redirect"] then
                    settings["redirect"] = v["settings_freedom_redirect"]
                end
            elseif v["protocol"] == "dns" then
                if v["settings_dns_network"] then
                    settings["network"] = v["settings_dns_network"]
                end
                if v["settings_dns_address"] then
                    settings["address"] = v["settings_dns_address"]
                end
                if v["settings_dns_port"] then
                    settings["port"] = tonumber(v["settings_dns_port"])
                end
            elseif v["protocol"] == "http" then
                local servers_atom = {}
                if v["settings_http_servers_address"] then
                    servers_atom["address"] = v["settings_http_servers_address"]
                end
                if v["settings_http_servers_port"] then
                    servers_atom["port"] = tonumber(v["settings_http_servers_port"])
                end
                local users_atom = {}
                if v["settings_http_servers_users_user"] then
                    users_atom["user"] = v["settings_http_servers_users_user"]
                end
                if v["settings_http_servers_users_pass"] then
                    users_atom["pass"] = v["settings_http_servers_users_pass"]
                end
                if next(users_atom) ~= nil then
                    servers_atom["users"] = {}
                    table.insert(servers_atom["users"], users_atom)
                end
                if next(servers_atom) ~= nil then
                    settings["servers"] = {}
                    table.insert(settings["servers"], servers_atom)
                end
            elseif v["protocol"] == "socks" then
                local servers_atom = {}
                if v["settings_socks_servers_address"] then
                    servers_atom["address"] = v["settings_socks_servers_address"]
                end
                if v["settings_socks_servers_port"] then
                    servers_atom["port"] = tonumber(v["settings_socks_servers_port"])
                end
                local users_atom = {}
                if v["settings_socks_servers_users_user"] then
                    users_atom["user"] = v["settings_socks_servers_users_user"]
                end
                if v["settings_socks_servers_users_pass"] then
                    users_atom["pass"] = v["settings_socks_servers_users_pass"]
                end
                if next(users_atom) ~= nil then
                    servers_atom["users"] = {}
                    table.insert(servers_atom["users"], users_atom)
                end
                if next(servers_atom) ~= nil then
                    settings["servers"] = {}
                    table.insert(settings["servers"], servers_atom)
                end
            elseif v["protocol"] == "vmess" then
                local vnext_atom = {}
                if v["settings_vmess_vnext_address"] then
                    vnext_atom["address"] = v["settings_vmess_vnext_address"]
                end
                if v["settings_vmess_vnext_port"] then
                    vnext_atom["port"] = tonumber(v["settings_vmess_vnext_port"])
                end
                local users_atom = {}
                if v["settings_vmess_vnext_users_id"] then
                    users_atom["id"] = v["settings_vmess_vnext_users_id"]
                end
                if v["settings_vmess_vnext_users_alterid"] then
                    users_atom["alterId"] = tonumber(v["settings_vmess_vnext_users_alterid"])
                end
                if v["settings_vmess_vnext_users_security"] then
                    users_atom["security"] = v["settings_vmess_vnext_users_security"]
                end
                if next(users_atom) ~= nil then
                    vnext_atom["users"] = {}
                    table.insert(vnext_atom["users"], users_atom)
                end
                if next(vnext_atom) ~= nil then
                    settings["vnext"] = {}
                    table.insert(settings["vnext"], vnext_atom)
                end
            elseif v["protocol"] == "shadowsocks" then
                local servers_atom = {}
                if v["settings_shadowsocks_servers_address"] then
                    servers_atom["address"] = v["settings_shadowsocks_servers_address"]
                end
                if v["settings_shadowsocks_servers_port"] then
                    servers_atom["port"] = tonumber(v["settings_shadowsocks_servers_port"])
                end
                if v["settings_shadowsocks_servers_method"] then
                    servers_atom["method"] = v["settings_shadowsocks_servers_method"]
                end
                if v["settings_shadowsocks_servers_password"] then
                    servers_atom["password"] = v["settings_shadowsocks_servers_password"]
                end
                if next(servers_atom) ~= nil then
                    settings["servers"] = {}
                    table.insert(settings["servers"], servers_atom)
                end
            elseif v["protocol"] == "trojan" then
                local servers_atom = {}
                if v["settings_trojan_servers_address"] then
                    servers_atom["address"] = v["settings_trojan_servers_address"]
                end
                if v["settings_trojan_servers_port"] then
                    servers_atom["port"] = tonumber(v["settings_trojan_servers_port"])
                end
                if v["settings_trojan_servers_password"] then
                    servers_atom["password"] = v["settings_trojan_servers_password"]
                end
                if v["settings_trojan_servers_flow"] then
                    servers_atom["flow"] = v["settings_trojan_servers_flow"]
                    xtls = true
                end
                if next(servers_atom) ~= nil then
                    settings["servers"] = {}
                    table.insert(settings["servers"], servers_atom)
                end
            elseif v["protocol"] == "vless" then
                local vnext_atom = {}
                if v["settings_vless_vnext_address"] then
                    vnext_atom["address"] = v["settings_vless_vnext_address"]
                end
                if v["settings_vless_vnext_port"] then
                    vnext_atom["port"] = tonumber(v["settings_vless_vnext_port"])
                end
                local users_atom = {}
                if v["settings_vless_vnext_users_id"] then
                    users_atom["id"] = v["settings_vless_vnext_users_id"]
                end
                if v["settings_vless_vnext_users_encryption"] then
                    users_atom["encryption"] = tonumber(v["settings_vless_vnext_users_encryption"])
                end
                if v["settings_vless_vnext_servers_flow"] then
                    users_atom["flow"] = v["settings_vless_vnext_servers_flow"]
                    xtls = true
                end
                if next(users_atom) ~= nil then
                    vnext_atom["users"] = {}
                    table.insert(vnext_atom["users"], users_atom)
                end
                if next(vnext_atom) ~= nil then
                    settings["vnext"] = {}
                    table.insert(settings["vnext"], vnext_atom)
                end
            end
            if next(settings) ~= nil then
                TempTable["settings"] = settings
            end
        end
        if v["ps_tag"] then
            TempTable["proxySettings"] = {}
            TempTable["proxySettings"]["tag"] = v["ps_tag"]
        end
        if v["mux_enable"] then
            TempTable["mux"] = {}
            TempTable["mux"]["enabled"] = true
            if v["mux_concurrency"] then
                TempTable["mux"]["concurrency"] = tonumber(v["mux_concurrency"])
            end
        end
        local streamSettings = {}
        if v["ss_network"] then
            streamSettings["network"] = v["ss_network"]
        end
        if v["ss_security_tls_enable"] then
            if xtls then
                streamSettings["security"] = "x" .. v["ss_security_tls_enable"]
            else
                streamSettings["security"] = v["ss_security_tls_enable"]
            end
            local tls = {}
            if v["ss_tls_servername"] then
                tls["serverName"] = v["ss_tls_servername"]
            end
            if v["ss_tls_rejectunknownsni"] then
                tls["rejectUnknownSni"] = true
            end
            if v["ss_tls_alpn"] then
                tls["alpn"] = split(v["ss_tls_alpn"], " ")
            end
            if v["ss_tls_allowinsecure"] then
                tls["allowInsecure"] = true
            end
            if v["ss_tls_minversion"] then
                tls["minVersion"] = v["ss_tls_minversion"]
            end
            if v["ss_tls_maxversion"] then
                tls["maxVersion"] = v["ss_tls_maxversion"]
            end
            if v["ss_tls_ciphersuites"] then
                tls["cipherSuites"] = split(v["ss_tls_ciphersuites"], " ")
            end
            if v["ss_tls_disablesystemroot"] then
                tls["disableSystemRoot"] = true
            end
            if v["ss_tls_enablesessionresumption"] then
                tls["enableSessionResumption"] = true
            end
            if v["ss_tls_fingerprint"] then
                tls["fingerprint"] = v["ss_tls_fingerprint"]
            end
            local certificates = {}
            if v["ss_tls_certificates_ocspstapling"] then
                certificates["ocspStapling"] = tonumber(v["ss_tls_certificates_ocspstapling"])
            end
            if v["ss_tls_certificates_onetimeloading"] then
                certificates["oneTimeLoading"] = true
            end
            if v["ss_tls_certificates_usage"] then
                certificates["usage"] = v["ss_tls_certificates_usage"]
            end
            if v["ss_tls_certificates_certificatefile"] then
                certificates["certificateFile"] = v["ss_tls_certificates_certificatefile"]
            end
            if v["ss_tls_certificates_keyfile"] then
                certificates["keyFile"] = v["ss_tls_certificates_keyfile"]
            end
            if next(certificates) ~= nil then
                tls["certificates"] = {}
                table.insert(tls["certificates"], certificates)
            end
            if xtls then
                streamSettings["xtlsSettings"] = tls
            else
                streamSettings["tlsSettings"] = tls
            end
        end
        if v["ss_network"] == "tcp" then
            local settings = {}
            if v["ss_tcp_header_type"] == "http" then
                settings["header"] = {}
                settings["header"]["type"] = "http"
                local request = {}
                if v["ss_tcp_header_request_version"] then
                    request["version"] = v["ss_tcp_header_request_version"]
                end
                if v["ss_tcp_header_request_method"] then
                    request["method"] = v["ss_tcp_header_request_method"]
                end
                if v["ss_tcp_header_request_path"] then
                    request["path"] = v["ss_tcp_header_request_path"]
                end
                if v["ss_tcp_header_request_headers"] then
                    request["headers"] = ListToMap(v["ss_tcp_header_request_headers"])
                end
                if next(request) ~= nil then
                    settings["header"]["request"] = request
                end
                local response = {}
                if v["ss_tcp_header_response_version"] then
                    response["version"] = v["ss_tcp_header_response_version"]
                end
                if v["ss_tcp_header_response_status"] then
                    response["status"] = v["ss_tcp_header_response_status"]
                end
                if v["ss_tcp_header_response_reason"] then
                    response["reason"] = v["ss_tcp_header_response_reason"]
                end
                if v["ss_tcp_header_response_headers"] then
                    response["headers"] = ListToMap(v["ss_tcp_header_response_headers"])
                end
                if next(response) ~= nil then
                    settings["header"]["response"] = response
                end
            end
            if next(settings) ~= nil then
                streamSettings["tcpSettings"] = settings
            end
        elseif v["ss_network"] == "kcp" then
            local settings = {}
            if v["ss_kcp_mtu"] then
                settings["mtu"] = tonumber(v["ss_kcp_mtu"])
            end
            if v["ss_kcp_tti"] then
                settings["tti"] = tonumber(v["ss_kcp_tti"])
            end
            if v["ss_kcp_uplinkcapacity"] then
                settings["uplinkCapacity"] = tonumber(v["ss_kcp_uplinkcapacity"])
            end
            if v["ss_kcp_downlinkcapacity"] then
                settings["downlinkCapacity"] = tonumber(v["ss_kcp_downlinkcapacity"])
            end
            if v["ss_kcp_congestion"] then
                settings["congestion"] = true
            end
            if v["ss_kcp_readbuffersize"] then
                settings["readBufferSize"] = tonumber(v["ss_kcp_readbuffersize"])
            end
            if v["ss_kcp_writebuffersize"] then
                settings["writeBufferSize"] = tonumber(v["ss_kcp_writebuffersize"])
            end
            if v["ss_kcp_header_type"] and v["ss_kcp_header_type"] ~= "none" then
                settings["header"] = {}
                settings["header"]["type"] = v["ss_kcp_header_type"]
            end
            if v["ss_kcp_seed"] then
                settings["seed"] = v["ss_kcp_seed"]
            end
            if next(settings) ~= nil then
                streamSettings["kcpSettings"] = settings
            end
        elseif v["ss_network"] == "ws" then
            local settings = {}
            if v["ss_ws_path"] then
                settings["path"] = v["ss_ws_path"]
            end
            if v["ss_ws_headers"] then
                settings["headers"] = ListToMap(v["ss_ws_headers"])
            end
            if next(settings) ~= nil then
                streamSettings["wsSettings"] = settings
            end
        elseif v["ss_network"] == "http" then
            local settings = {}
            if v["ss_http_host"] then
                settings["host"] = v["ss_http_host"]
            end
            if v["ss_http_path"] then
                settings["path"] = v["ss_http_path"]
            end
            if v["ss_http_readidletimeout"] then
                settings["read_idle_timeout"] = tonumber(v["ss_http_readidletimeout"])
            end
            if v["ss_http_healthchecktimeout"] then
                settings["health_check_timeout"] = tonumber(v["ss_http_healthchecktimeout"])
            end
            if next(settings) ~= nil then
                streamSettings["httpSettings"] = settings
            end
        elseif v["ss_network"] == "quic" then
            local settings = {}
            if v["ss_quic_security"] then
                settings["security"] = v["ss_quic_security"]
                if v["ss_quic_security"] ~= nil and v["ss_quic_security"] ~= "" and v["ss_quic_security"] ~= "none" then
                    if v["ss_quic_key"] then
                        settings["key"] = v["ss_quic_key"]
                    end
                end
            end
            if v["ss_quic_header_type"] and v["ss_quic_header_type"] ~= "none" and v["ss_quic_header_type"] ~= "" then
                settings["header"] = {}
                settings["header"]["type"] = v["ss_quic_header_type"]
            end
            if next(settings) ~= nil then
                streamSettings["quicSettings"] = settings
            end
        elseif v["ss_network"] == "grpc" then
            local settings = {}
            if v["ss_grpc_servicename"] then
                settings["serviceName"] = v["ss_grpc_servicename"]
            end
            if v["ss_grpc_multimode"] then
                settings["multiMode"] = true
            end
            if v["ss_grpc_idletimeout"] then
               settings["idle_timeout"]  = tonumber(v["ss_grpc_idletimeout"])
            end
            if v["ss_grpc_healthchecktimeout"] then
                settings["health_check_timeout"]  = tonumber(v["ss_grpc_healthchecktimeout"])
            end
            if v["ss_grpc_permitwithoutstream"] then
                settings["permit_without_stream"] = true
            end
            if next(settings) ~= nil then
                streamSettings["grpcSettings"] = settings
            end
        end
        if next(streamSettings) ~= nil then
            TempTable["streamSettings"] = streamSettings
        end
        table.insert(outbounds, TempTable)
    end
end

for _, v in ipairs(RoutingGlobalCfg) do
    if v["domainstrategy"] then
        routing["domainStrategy"] = v["domainstrategy"]
    end
end

for _, v in ipairs(RoutingRuleCfg) do
    if v["enable"] then
        local s = {}
        if v["alias"] then
            s["alias"] = v["alias"]
        end
        if v["type"] then
            s["type"] = v["type"]
        end
        if v["domain"] then
            s["domain"] = v["domain"]
        end
        if v["ip"] then
            s["ip"] = v["ip"]
        end
        if v["port"] then
            s["port"] = table.concat(v["port"], ",")
        end
        if v["sourceport"] then
            s["sourceport"] = table.concat(v["sourceport"], ",")
        end
        if v["network"] then
            s["network"] = table.concat(split(v["network"], " "), ",")
        end
        if v["source"] then
            s["source"] = v["source"]
        end
        if v["inboundtag"] then
            s["inboundTag"] = v["inboundtag"]
        end
        if v["protocol"] then
            s["protocol"] = split(v["protocol"], " ")
        end
        if v["attrs"] then
            s["attrs"] = v["attrs"]
        end
        if v["outboundtag"] then
            s["outboundTag"] = v["outboundtag"]
        end
        if v["balancertag"] then
            s["balancerTag"] = v["balancertag"]
        end
        table.insert(routing_rule, s)
    end
end

if next(routing_rule) ~= nil then
    routing["rules"] = routing_rule
end

for _, v in ipairs(RoutingBalancerCfg) do
    if v["enable"] then
        local s = {}
        if v["tag"] then
            s["tag"] = v["tag"]
        end
        if v["selector"] then
            s["selector"] = v["selector"]
        end
        table.insert(routing_balancer, s)
    end
end

if next(routing_balancer) ~= nil then
    routing["balancers"] = routing_balancer
end

----

if LogCfg[1]["access_log"] then
    log["access"] = LogCfg[1]["access_log"]
end
if LogCfg[1]["loglevel"] then
    log["loglevel"] = LogCfg[1]["loglevel"]
end
if LogCfg[1]["loglevel"] ~= "none" then
    if LogCfg[1]["error_log"] and LogCfg[1]["error_log"] ~= "/dev/null" then
        log["error"] = LogCfg[1]["error_log"]
    end
end
if LogCfg[1]["dns_log"] then
    if next(dns) ~= nil then
        log["dnslog"] = true
    end
end

---
local cfg = {}
if next(log) ~= nil then
    cfg["log"] = log
end
if next(dns) ~= nil then
    cfg["dns"] = dns
end
if next(outbounds) ~= nil then
    cfg["outbounds"] = outbounds
end
if next(inbounds) ~= nil then
    cfg["inbounds"] = inbounds
end
if next(routing) ~= nil then
    cfg["routing"] = routing
end

cfgjson = jsonc.stringify(cfg, 1)

cfgfile = io.open(gen_config_file, "w")
io.output(cfgfile)
io.write(cfgjson)
io.write("\n")
io.close(cfgfile)

return