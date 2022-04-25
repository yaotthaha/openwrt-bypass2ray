#!/usr/bin/lua

local support = require "luci.model.cbi.bypass2ray.support"
local appname = support.appname
local uci = require "luci.model.uci".cursor()
local sys = require "luci.sys"
local jsonc = require 'luci.jsonc'
local md5 = require "md5"

local subsid = arg[1]

if subsid == "" or subsid == nil then
    return -1
end

local alias = uci:get(appname, subsid, "alias")
local peerlist = uci:get_list(appname, subsid, "peerlist")
local include = uci:get(appname, subsid, "include")
local exclude = uci:get(appname, subsid, "exclude")
local mode = uci:get(appname, subsid, "mode") or "1"
local so_mark = uci:get(appname, subsid, "so_mark") or ""

support.LogToFile("==== 添加订阅节点到出站" .. alias .. " ====")

if alias == nil or alias == "" then
    support.LogToFile("获取信息失败")
    return -1
end

if type(peerlist) ~= "table" or #peerlist <= 0 then
    support.LogToFile("获取节点列表失败")
    return -1
end

function Filter(keyword) -- True => Include False => Exclude
    print(keyword)
    if mode == "1" then
        local ok = true
        if type(include) == "table" then
            for _, v in ipairs(include) do
                if keyword:find(v, 1, true) then
                    ok = true
                end
            end
        end
        if type(exclude) == "table" then
            for _, v in ipairs(exclude) do
                if keyword:find(v, 1, true) then
                    ok = false
                end
            end
        end
        return ok
    elseif mode == "2" then
        local ok = true
        if type(exclude) == "table" then
            for _, v in ipairs(exclude) do
                if keyword:find(v, 1, true) then
                    ok = false
                end
            end
        end
        if type(include) == "table" then
            for _, v in ipairs(include) do
                if keyword:find(v, 1, true) then
                    ok = true
                end
            end
        end
        return ok
    else
        return true
    end
end

-- Add VMess
function AddVMess(t, uuid, post_func) -- t => table
    if t["v"] == nil or t["v"] ~= "2" then
        return -1  -- 版本信息错误
    end
    local cfg_alias
    local cfg_address
    local cfg_port
    local cfg_vmess_id
    local cfg_vmess_alterid
    local cfg_vmess_security = "auto"
    local cfg_network
    local cfg_type
    local cfg_host
    local cfg_security_kcp
    local cfg_path
    local cfg_key_quic
    local cfg_seed_kcp
    local cfg_tls
    local cfg_sni
    --
    if t["ps"] == nil or t["ps"] == "" then
        return -1
    else
        cfg_alias = t["ps"]
    end
    --
    if t["add"] == nil or t["add"] == "" then
        return -1
    else
        cfg_address = t["add"]
    end
    if t["port"] == nil or t["port"] == "" then
        return -1
    else
        cfg_port = tonumber(t["port"])
    end
    if t["id"] == nil or t["id"] == "" then
        return -1
    else
        cfg_vmess_id = t["id"]
    end
    if t["aid"] == nil or t["aid"] == "" then
        return -1
    else
        cfg_vmess_alterid = tonumber(t["aid"])
    end
    if t["scy"] ~= nil and t["scy"] ~= "" then
        cfg_vmess_security = t["scy"]
    end
    if t["net"] == "tcp" then
        cfg_network = "tcp"
        if t["type"] == "none" then
            cfg_type = "none"
        elseif t["type"] == "http" then
            cfg_type = "http"
        end
        if t["host"] ~= nil  and t["host"] ~= "" then
            cfg_host = support.split(t["host"], ",")
        end
        if t["tls"] ~= nil and t["tls"] ~= "" then
            cfg_tls = "tls"
            if t["sni"] ~= nil and t["sni"] ~= "" then
                cfg_sni = t["sni"]
            end
        end
    elseif t["net"] == "kcp" then
        cfg_network = "kcp"
        if t["type"] == "none" then
            cfg_type = "none"
        elseif t["type"] == "srtp" then
            cfg_type = "srtp"
        elseif t["type"] == "utp" then
            cfg_type = "utp"
        elseif t["type"] == "wechat-video" then
            cfg_type = "wechat-video"
        end
        if t["path"] ~= nil and t["path"] ~= "" then
            cfg_seed_kcp = t["path"]
        end
        if t["tls"] ~= nil and t["tls"] ~= "" then
            cfg_tls = "tls"
            if t["sni"] ~= nil and t["sni"] ~= "" then
                cfg_sni = t["sni"]
            end
        end
    elseif t["net"] == "ws" then
        cfg_network = "ws"
        if t["host"] ~= nil and t["host"] ~= "" then
            cfg_host = t["host"]
        end
        if t["path"] ~= nil and t["path"] ~= "" then
            cfg_path = t["path"]
        end
        if t["tls"] ~= nil and t["tls"] ~= "" then
            cfg_tls = "tls"
            if t["sni"] ~= nil and t["sni"] ~= "" then
                cfg_sni = t["sni"]
            elseif t["host"] ~= nil and t["host"] ~= "" then
                cfg_sni = t["host"]
            end
        end
    elseif t["net"] == "h2" then
        cfg_network = "http"
        if t["host"] ~= nil and t["host"] ~= "" then
            cfg_host = t["host"]
        end
        if t["path"] ~= nil and t["path"] ~= "" then
            cfg_path = t["path"]
        end
        if t["tls"] ~= nil and t["tls"] ~= "" then
            cfg_tls = "tls"
            if t["sni"] ~= nil and t["sni"] ~= "" then
                cfg_sni = t["sni"]
            elseif t["host"] ~= nil and t["host"] ~= "" then
                cfg_sni = t["host"]
            end
        end
    elseif t["net"] == "quic" then
        cfg_network = "quic"
        if t["type"] == "none" then
            cfg_type = "none"
        elseif t["type"] == "srtp" then
            cfg_type = "srtp"
        elseif t["type"] == "utp" then
            cfg_type = "utp"
        elseif t["type"] == "wechat-video" then
            cfg_type = "wechat-video"
        end
        if t["host"] ~= nil and t["host"] ~= "" then
            cfg_security_kcp = t["host"]
        end
        if t["path"] ~= nil and t["path"] ~= "" then
            cfg_key_quic = t["path"]
        end
        if t["tls"] ~= nil and t["tls"] ~= "" then
            cfg_tls = "tls"
            if t["sni"] ~= nil and t["sni"] ~= "" then
                cfg_sni = t["sni"]
            end
        end
    else
        return -1
    end
    --
    if type(post_func) == "function" then
        post_func(t, uuid)
    end
    uci:set(appname, uuid, "outbound")
    uci:set(appname, uuid, "enable", "0")
    uci:set(appname, uuid, "alias", alias .. " - " .. cfg_alias)
    --
    uci:set(appname, uuid, "subscribe_tag", subsid)
    uci:set(appname, uuid, "subscribe_unique_id", md5.sumhexa(jsonc.stringify(t, 1)))
    uci:set(appname, uuid, "tag", string.sub(subsid, 1, 16) .. string.sub(uuid, 1, 16))
    --
    uci:set(appname, uuid, "protocol", "vmess")
    uci:set(appname, uuid, "settings_vmess_vnext_address", cfg_address)
    uci:set(appname, uuid, "settings_vmess_vnext_port", cfg_port)
    uci:set(appname, uuid, "settings_vmess_vnext_users_id", cfg_vmess_id)
    uci:set(appname, uuid, "settings_vmess_vnext_users_alterid", cfg_vmess_alterid)
    uci:set(appname, uuid, "settings_vmess_vnext_users_security", cfg_vmess_security)
    uci:set(appname, uuid, "ss_network", cfg_network)
    if cfg_network == "tcp" then
        uci:set(appname, uuid, "ss_tcp_header_type", cfg_type)
        if cfg_host ~= nil and type(cfg_host) == "table" then
            local hostLst = {}
                for _, v in ipairs(cfg_host) do
                    table.insert(hostLst, "Host:" .. v)
                end
                if #hostLst > 0 then
                uci:set_list(appname, uuid, "ss_tcp_header_response_headers", hostLst)
            end
        end
    elseif cfg_network == "kcp" then
        uci:set(appname, uuid, "ss_kcp_header_type", cfg_type)
        if cfg_seed_kcp ~= nil and cfg_seed_kcp ~= "" then
            uci:set(appname, uuid, "ss_kcp_seed", cfg_seed_kcp)
        end
    elseif cfg_network == "ws" then
        if cfg_host ~= nil and cfg_host ~= "" then
            local hostLst = {}
            table.insert(hostLst, "Host:" .. cfg_host)
            uci:set_list(appname, uuid, "ss_ws_headers", hostLst)
        end
        if cfg_path ~= nil and cfg_path ~= "" then
            uci:set(appname, uuid, "ss_ws_path", cfg_path)
        end
    elseif cfg_network == "http" then
        if cfg_host ~= nil and cfg_host ~= "" then
            local hostLst = {}
            table.insert(hostLst, "Host:" .. cfg_host)
            uci:set_list(appname, uuid, "ss_http_host", hostLst)
        end
        if cfg_path ~= nil and cfg_path ~= "" then
            uci:set(appname, uuid, "ss_http_path", cfg_path)
        end
    elseif cfg_network == "quic" then
        uci:set(appname, uuid, "ss_quic_header_type", cfg_type)
        if cfg_security_kcp ~= nil and cfg_security_kcp ~= "" then
            uci:set(appname, uuid, "ss_quic_security", cfg_security_kcp)
        end
        if cfg_key_quic ~= nil and cfg_key_quic ~= "" then
            uci:set(appname, uuid, "ss_quic_key", cfg_key_quic)
        end
    end
    if cfg_tls ~= nil and cfg_tls ~= "" then
        uci:set(appname, uuid, "ss_security_tls_enable", cfg_tls)
        if cfg_sni ~= nil and cfg_sni ~= "" then
            uci:set(appname, uuid, "ss_tls_servername", cfg_sni)
        end
    end
    --
    return 0
end

-- Add Shadowsocks
function AddShadowsocks(t, uuid, post_func)
	if t["address"] == nil or t["address"] == "" or t["security"] == nil or t["security"] == "" or t["password"] == nil or t["password"] == "" or t["port"] == nil or t["port"] == "" then
		return -1
	end
	if t["security"] ~= "aes-256-gcm" and t["security"] ~= "aes-128-gcm" and t["security"] ~= "chacha20-poly1305" and t["security"] ~= "chacha20-ietf-poly1305" then
		return -1
	end
	if tonumber(t["port"]) == nil then
		return -1
	end
	t["alias"] = support.urlDecode(t["alias"])
    if type(post_func) == "function" then
        post_func(t, uuid)
    end
	uci:set(appname, uuid, "outbound")
	uci:set(appname, uuid, "enable", "0")
	uci:set(appname, uuid, "alias", alias .. " - " ..  t["alias"])
    --
	uci:set(appname, uuid, "subscribe_tag", subsid)
    uci:set(appname, uuid, "subscribe_unique_id", md5.sumhexa(jsonc.stringify(t, 1)))
    uci:set(appname, uuid, "tag", string.sub(subsid, 1, 16) .. string.sub(uuid, 1, 16))
    --
	uci:set(appname, uuid, "protocol", "shadowsocks")
	uci:set(appname, uuid, "settings_shadowsocks_servers_address", t["address"])
	uci:set(appname, uuid, "settings_shadowsocks_servers_port", tonumber(t["port"]))
	uci:set(appname, uuid, "settings_shadowsocks_servers_method", t["security"])
	uci:set(appname, uuid, "settings_shadowsocks_servers_password", t["password"])
    --
    return 0
end

local NotDelPeers = {}
local err = 0
local filter = 0
local add = 0
local del = 0
local jump = 0
local modify = 0

local now_peers = {}
uci:foreach(appname, "outbound", function(s)
    if s["subscribe_tag"] ~= nil and s["subscribe_tag"] ~= "" then
        if s["subscribe_tag"] == subsid then
            table.insert(now_peers, s)
        end
    end
end)

for _, v in pairs(peerlist) do
    function Do()
        local linkN = string.gsub(v, "://", ":")
	    local linkLst = support.split(linkN, ":")
	    if linkLst[1] == "vmess" then
		    local linkLst_copy = linkLst
		    table.remove(linkLst_copy, 1)
		    local M = table.concat(linkLst_copy, ":")
		    local msg = support.base64Decode(M)
		    ---- From https://github.com/2dust/v2rayN/wiki/%E5%88%86%E4%BA%AB%E9%93%BE%E6%8E%A5%E6%A0%BC%E5%BC%8F%E8%AF%B4%E6%98%8E(ver-2)
		    local cfgjson = jsonc.parse(msg)
            if cfgjson["ps"] == nil or cfgjson["ps"] == "" then
                err = err + 1
                return
            end
            if not Filter(cfgjson["ps"]) then
                filter = filter + 1
                return
            end
            local uuid = support.gen_uuid()
            local md5sum = md5.sumhexa(jsonc.stringify(cfgjson, 1))
            for _, V in pairs(now_peers) do
                if support.base64Encode(V["alias"]) == support.base64Encode(alias .. " - " .. cfgjson["ps"]) then
                    if V["subscribe_unique_id"] ~= md5sum then
                        uci:delete(appname, V[".name"])
                        uuid = V[".name"]
                        modify = modify + 1
                    else
                        jump = jump + 1
                        return
                    end
                end
            end
		    local rt = AddVMess(cfgjson, uuid, function(_, u)
                if so_mark ~= "" then
                    uci:set(appname, u, "ss_sockopt_mark", so_mark)
                end
            end)
            if rt == 0 then
                add = add + 1
            elseif rt == -1 then
                err = err + 1
            end
            table.insert(NotDelPeers, alias .. " - " .. cfgjson["ps"])
            return 0
	    elseif linkLst[1] == "ss" then
    		local linkLst_copy = linkLst
		    table.remove(linkLst_copy, 1)
		    local info = table.concat(linkLst_copy, ":")
            local security, password, ss_alias, address, port
	        local t1 = support.split(info, '@')
	        if #t1 ~= 2 then
        		return -1, 0
    	    end
    	    local b = support.split(support.base64Decode(t1[1]), ":")
    	    security = b[1]
    	    password = b[2]
    	    local t2 = support.split(t1[2], '#')
    	    if #t2 ~= 1 and #t2 ~= 2 then
    		    return -1, 0
	        end
	        if #t2 == 2 then
        		ss_alias = t2[2]
    	    end
    	    local t3 = support.split(t2[1], ':')
    	    port = t3[#t3]
    	    table.remove(t3, #t3)
    	    address = table.concat(t3, ":")
            local cfgjson = {}
            cfgjson["alias"] = ss_alias
            cfgjson["address"] = address
            cfgjson["port"] = port
            cfgjson["password"] = password
            cfgjson["security"] = security
            --
            if cfgjson["alias"] == nil or cfgjson["alias"] == "" then
                err = err + 1
                return
            end
            if not Filter(cfgjson["alias"]) then
                filter = filter + 1
                return
            end
            local uuid = support.gen_uuid()
            local md5sum = md5.sumhexa(jsonc.stringify(cfgjson, 1))
            for _, V in pairs(now_peers) do
                if support.base64Encode(V["alias"]) == support.base64Encode(alias .. " - " .. cfgjson["alias"]) then
                    if V["subscribe_unique_id"] ~= md5sum then
                        uci:delete(appname, V[".name"])
                        uuid = V[".name"]
                        modify = modify + 1
                    else
                        jump = jump + 1
                        return
                    end
                end
            end
		    local rt = AddShadowsocks(cfgjson, uuid, function(_, u)
                if so_mark ~= "" then
                    uci:set(appname, u, "ss_sockopt_mark", so_mark)
                end
            end)
            if rt == 0 then
                add = add + 1
            elseif rt == -1 then
                err = err + 1
            end
            table.insert(NotDelPeers, alias .. " - " .. cfgjson["alias"])
            return 0
	    else
    		return -1
    	end
    end
    Do()
end

local Del = {}

for _, v in pairs(now_peers) do
    for _, V in pairs(NotDelPeers) do
        if V == support.base64Encode(v["alias"]) then
            table.insert(Del, v[".name"])
        end
    end
end

for _, v in pairs(Del) do
    uci:delete(appname, v)
end

uci:commit(appname)
support.LogToFile("添加节点：" .. tostring(add))
support.LogToFile("删除节点：" .. tostring(del))
support.LogToFile("无效节点：" .. tostring(err))
support.LogToFile("跳过节点：" .. tostring(jump))
support.LogToFile("调整节点：" .. tostring(modify))
support.LogToFile("过滤节点：" .. tostring(filter))
