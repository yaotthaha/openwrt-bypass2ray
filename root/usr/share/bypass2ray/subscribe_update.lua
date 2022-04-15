#!/usr/bin/lua

local support = require "luci.model.cbi.bypass2ray.support"
local appname = support.appname
local uci = require "luci.model.uci".cursor()
local sys = require "luci.sys"
local jsonc = require 'luci.jsonc'

local subsid = arg[1]

if subsid == "" or subsid == nil then
    return 0
end

local cfg = uci:get_all(appname, subsid)

if cfg == nil then
    return 0
end

local alias = cfg["alias"] or "?"
local url = cfg["url"]
local mode = cfg["mode"] or "1"
local shell = cfg["shell"] or "curl -kfsSL '::url::' --user-agent '\'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.122 Safari/537.36\'' --retry 3 --connect-timeout 3 --max-time 30"
local include = cfg["include"]
local exclude = cfg["exclude"]

support.LogToFile("==== 更新订阅 " .. alias .. " ====")

if url == nil or url == "" or mode == nil or mode == "" or shell == nil or shell == "" then
    support.LogToFile("找不到 `url` / `mode` / `shell`")
    return -1
end

local cmd = string.gsub(shell, "::url::", url)
local result = sys.exec(cmd)
local resultDec = support.base64Decode(result)
local peers = support.split(string.gsub(resultDec, "\r\n", "\n"), "\n")

if type(peers) ~= "table" then
    support.LogToFile("获取节点失败")
    return -1
else
	local peer_copy = peers
	for k, v in pairs(peer_copy) do
		if v == "" then
			table.remove(peers, k)
		end
	end
	if table.getn(peers) <= 0 then
    	support.LogToFile("获取节点失败")
    	return -1
	end
end

local add = 0
local del = 0
local err = 0
local filter = 0

function Filter(keyword)
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

function Add(link, commit)
	local linkN = string.gsub(link, "://", ":")
	local linkLst = support.split(linkN, ":")
	if linkLst[1] == "vmess" then
		local linkLst_copy = linkLst
		table.remove(linkLst_copy, 1)
		local M = table.concat(linkLst_copy, ":")
		local msg = support.base64Decode(M)
		---- From https://github.com/2dust/v2rayN/wiki/%E5%88%86%E4%BA%AB%E9%93%BE%E6%8E%A5%E6%A0%BC%E5%BC%8F%E8%AF%B4%E6%98%8E(ver-2)
		local cfgjson = jsonc.parse(msg)
		if cfgjson["v"] == nil or cfgjson["v"] ~= "2" then
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
		if cfgjson["ps"] == nil or cfgjson["ps"] == "" then
			return -1
		else
			cfg_alias = cfgjson["ps"]
		end
        --
        if not Filter(cfg_alias) then
            return 1
        end
        --
		if cfgjson["add"] == nil or cfgjson["add"] == "" then
			return -1
		else
			cfg_address = cfgjson["add"]
		end
		if cfgjson["port"] == nil or cfgjson["port"] == "" then
			return -1
		else
			cfg_port = tonumber(cfgjson["port"])
		end
		if cfgjson["id"] == nil or cfgjson["id"] == "" then
			return -1
		else
			cfg_vmess_id = cfgjson["id"]
		end
		if cfgjson["aid"] == nil or cfgjson["aid"] == "" then
			return -1
		else
			cfg_vmess_alterid = tonumber(cfgjson["aid"])
		end
		if cfgjson["scy"] ~= nil and cfgjson["scy"] ~= "" then
			cfg_vmess_security = cfgjson["scy"]
		end
		if cfgjson["net"] == "tcp" then
			cfg_network = "tcp"
			if cfgjson["type"] == "none" then
				cfg_type = "none"
			elseif cfgjson["type"] == "http" then
				cfg_type = "http"
			end
			if cfgjson["host"] ~= nil  and cfgjson["host"] ~= "" then
				cfg_host = support.split(cfgjson["host"], ",")
			end
		elseif cfgjson["net"] == "kcp" then
			cfg_network = "kcp"
			if cfgjson["type"] == "none" then
				cfg_type = "none"
			elseif cfgjson["type"] == "srtp" then
				cfg_type = "srtp"
			elseif cfgjson["type"] == "utp" then
				cfg_type = "utp"
			elseif cfgjson["type"] == "wechat-video" then
				cfg_type = "wechat-video"
			end
			if cfgjson["path"] ~= nil and cfgjson["path"] ~= "" then
				cfg_seed_kcp = cfgjson["path"]
			end
		elseif cfgjson["net"] == "ws" then
			cfg_network = "ws"
			if cfgjson["host"] ~= nil and cfgjson["host"] ~= "" then
				cfg_host = cfgjson["host"]
			end
			if cfgjson["path"] ~= nil and cfgjson["path"] ~= "" then
				cfg_path = cfgjson["path"]
			end
		elseif cfgjson["net"] == "h2" then
			cfg_network = "http"
			if cfgjson["host"] ~= nil and cfgjson["host"] ~= "" then
				cfg_host = cfgjson["host"]
			end
			if cfgjson["path"] ~= nil and cfgjson["path"] ~= "" then
				cfg_path = cfgjson["path"]
			end
		elseif cfgjson["net"] == "quic" then
			cfg_network = "quic"
			if cfgjson["type"] == "none" then
				cfg_type = "none"
			elseif cfgjson["type"] == "srtp" then
				cfg_type = "srtp"
			elseif cfgjson["type"] == "utp" then
				cfg_type = "utp"
			elseif cfgjson["type"] == "wechat-video" then
				cfg_type = "wechat-video"
			end
			if cfgjson["host"] ~= nil and cfgjson["host"] ~= "" then
				cfg_security_kcp = cfgjson["host"]
			end
			if cfgjson["path"] ~= nil and cfgjson["path"] ~= "" then
				cfg_key_quic = cfgjson["path"]
			end
		else
			return -1
		end
		if cfgjson["tls"] ~= nil and cfgjson["tls"] ~= "" then
			cfg_tls = "tls"
		end
		if cfgjson["sni"] ~= nil and cfgjson["sni"] ~= "" then
			cfg_sni = cfgjson["sni"]
		end
        local uuid = support.gen_uuid()
		uci:set(appname, uuid, "outbound")
		uci:set(appname, uuid, "enable", "0")
		uci:set(appname, uuid, "alias", cfg_alias)
        --
		uci:set(appname, uuid, "subscribe_tag", subsid)
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
				    table.insert(hostLst, "Host: " .. v)
			    end
			    if table.getn(hostLst) > 0 then
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
				table.insert(hostLst, "Host: " .. cfg_host)
				uci:set_list(appname, uuid, "ss_ws_headers", hostLst)
			end
			if cfg_path ~= nil and cfg_path ~= "" then
				uci:set(appname, uuid, "ss_ws_path", cfg_path)
			end
		elseif cfg_network == "http" then
			if cfg_host ~= nil and cfg_host ~= "" then
				local hostLst = {}
				table.insert(hostLst, "Host: " .. cfg_host)
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
		if commit then
            uci:commit(appname)
        end
	elseif linkLst[1] == "ss" then
		local linkLst_copy = linkLst
		table.remove(linkLst_copy, 1)
		local info = table.concat(linkLst_copy, ":")
		local security, password, alias, address, port
		local t1 = support.split(info, '@')
		if table.getn(t1) ~= 2 then
			return -1
		end
		local b = support.split(support.base64Decode(t1[1]), ":")
		security = b[1]
		password = b[2]
		local t2 = support.split(t1[2], '#')
		if table.getn(t2) ~= 1 and table.getn(t2) ~= 2 then
			return -1
		end
		if table.getn(t2) == 2 then
			alias = t2[2]
		end
		local t3 = support.split(t2[1], ':')
		port = t3[table.getn(t3)]
		table.remove(t3, table.getn(t3))
		address = table.concat(t3, ":")
		--
		if address == nil or address == "" or security == nil or security == "" or password == nil or password == "" or port == nil or port == "" then
			return -1
		end
		if security ~= "aes-256-gcm" and security ~= "aes-128-gcm" and security ~= "chacha20-poly1305" and security ~= "chacha20-ietf-poly1305" then
			return -1
		end
		if tonumber(port) == nil then
			return -1
		end
		if alias == nil then
			alias = support.gen_uuid(8)
		else
			alias = support.urlDecode(alias)
			if not Filter(alias) then
				return 1
			end
		end
		local uuid = support.gen_uuid()
		uci:set(appname, uuid, "outbound")
		uci:set(appname, uuid, "enable", "0")
		uci:set(appname, uuid, "alias", alias)
        --
		uci:set(appname, uuid, "subscribe_tag", subsid)
        uci:set(appname, uuid, "tag", string.sub(subsid, 1, 16) .. string.sub(uuid, 1, 16))
        --
		uci:set(appname, uuid, "protocol", "shadowsocks")
		uci:set(appname, uuid, "settings_shadowsocks_servers_address", address)
		uci:set(appname, uuid, "settings_shadowsocks_servers_port", tonumber(port))
		uci:set(appname, uuid, "settings_shadowsocks_servers_method", security)
		uci:set(appname, uuid, "settings_shadowsocks_servers_password", password)
		if commit then
            uci:commit(appname)
        end
	else
		return -1
	end
end

function Del(link, commit)
	local linkN = string.gsub(link, "://", ":")
	local linkLst = support.split(linkN, ":")
	if linkLst[1] == "vmess" or linkLst[1] == "ss" then
		local cfgjson = jsonc.parse(linkLst[2])
		if cfgjson["v"] == nil or cfgjson["v"] ~= "2" then
			return -1  -- 版本信息错误
		end
		local sid
		uci:foreach(appname, "outbound", function(s)
			if s["subscribe_tag"] ~= nil and s["subscribe_tag"] ~= "" and s["subscribe_tag"] == subsid and support.base64Encode(s["alias"]) == support.base64Encode(cfgjson["ps"]) then
				sid = s[".name"]
			end
		end)
		if sid ~= nil then
			uci:delete(appname, sid)
			if commit ~= nil then
				uci:commit(appname)
			end
		else
			return -1
		end
	end
end

local NeedAdd = {}
local NeedDel = {}

local old_list = uci:get(appname, subsid, "peerlist")
if old_list == nil or type(old_list) == "table" and table.getn(old_list) <= 0 then
	NeedAdd = peers
	uci:set_list(appname, subsid, "peerlist", peers)
else
	local Temp = {}
	for _, v in pairs(peers) do
		if Temp[v] == nil then
			Temp[v] = 0
		end
	end
	for _, v in pairs(old_list) do
		if Temp[v] == nil then
			Temp[v] = -1
		else
			Temp[v] = Temp[v] + 1
		end
	end
	for k, v in pairs(Temp) do
		if v == 0 then
			-- New => yes Old => no
			table.insert(NeedAdd, k)
		elseif v == -1 then
			-- New => no Old => yes
			table.insert(NeedDel, k)
		elseif v > 0 then
			-- New => yes Old => yes
		end
	end
	uci:set_list(appname, subsid, "peerlist", peers)
end


for k, v in pairs(NeedAdd) do
    local resp = Add(v, false)
    if resp == -1 then
        err = err + 1
    else
		add = add + 1
		if resp == 1 then
			filter = filter + 1
		end
    end
end

for k, v in pairs(NeedDel) do
    local resp = Del(v, false)
    if resp == -1 then
        err = err + 1
    else
		del = del + 1
    end
end

uci:commit(appname)
support.LogToFile("添加节点：" .. tostring(add))
support.LogToFile("删除节点：" .. tostring(del))
support.LogToFile("无效节点：" .. tostring(err))
support.LogToFile("过滤节点：" .. tostring(filter))
