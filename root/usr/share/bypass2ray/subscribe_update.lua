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
	if #peers <= 0 then
    	support.LogToFile("获取节点失败")
    	return -1
	end
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

local filter = 0

local peers_clone = peers
for k, v in pairs(peers_clone) do
	if not Filter(v) then
		table.remove(peers, k)
		filter = filter + 1
	end
end

uci:delete(appname, subsid, "peerlist")
uci:set_list(appname, subsid, "peerlist", peers)
uci:commit(appname)

support.LogToFile("添加节点：" .. tostring(#peers))
support.LogToFile("过滤节点：" .. tostring(filter))
