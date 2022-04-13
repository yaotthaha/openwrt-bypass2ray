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
local shell = cfg["shell"] or "curl -kfsSL '::url::' --user-agent 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.122 Safari/537.36' --retry 3 --connect-timeout 3"
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
elseif table.getn(peers) <= 0 then
    support.LogToFile("获取节点失败")
    return -1
end

local all = 0
local err = 0
local filter = 0

function FindExistPeer(subscribe_peerid)
    local exist
    uci:foreach(appname, "outbound", function(s)
        if s["subscribe_peerid"] ~= nil and s["subscribe_peerid"] == subscribe_peerid then
            exist = s[".name"]
        end
    end)
    return exist
end

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

function Do(link, commit)
	local linkN = string.gsub(link, "://", ":")
	local linkLst = support.split(linkN, ":")
	if linkLst[1] == "vmess" then
		local msg = support.base64Decode(linkLst[2])
		---- From https://github.com/2dust/v2rayN/wiki/%E5%88%86%E4%BA%AB%E9%93%BE%E6%8E%A5%E6%A0%BC%E5%BC%8F%E8%AF%B4%E6%98%8E(ver-2)
		local cfgjson = jsonc.parse(msg)
        print(jsonc.stringify(cfgjson, 1))
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
        local exist = FindExistPeer(support.base64Encode(cfg_alias))
        if exist ~= nil then
            uci:delete(appname, exist)
        end
        local uuid = support.gen_uuid()
		uci:set(appname, uuid, "outbound")
		uci:set(appname, uuid, "enable", "0")
		uci:set(appname, uuid, "alias", cfg_alias)
        --
		uci:set(appname, uuid, "subscribe_tag", subsid)
        uci:set(appname, uuid, "subscribe_peerid", support.base64Encode(cfg_alias))
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
		return 1
	else
		return -1
	end
end

for k, v in pairs(peers) do
    print(v)
    all = all + 1
    local resp = Do(v, false)
    if resp == -1 then
        err = err + 1
    elseif resp == 1 then
        filter = filter + 1
    end
end

uci:commit(appname)
support.LogToFile("总节点：" .. tostring(all))
support.LogToFile("无效节点：" .. tostring(err))
support.LogToFile("过滤节点：" .. tostring(filter))
