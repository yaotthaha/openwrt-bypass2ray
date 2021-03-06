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
local shell = cfg["shell"] or ("curl -kfsSL '::url::' --user-agent '" .. support.ua .. "' --retry 3 --connect-timeout 3 --max-time 30")


support.LogToFile("==== 更新订阅 " .. alias .. " ====")

if url == nil or url == "" or shell == nil or shell == "" then
    support.LogToFile("找不到 `url` / `shell`")
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

uci:delete(appname, subsid, "peerlist")
uci:set_list(appname, subsid, "peerlist", peers)
uci:commit(appname)

support.LogToFile("添加节点：" .. tostring(#peers))
