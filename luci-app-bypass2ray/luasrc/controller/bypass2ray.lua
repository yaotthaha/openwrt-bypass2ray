-- Copyright (C) 2022 yaott
local http = require "luci.http"
local uci = require "luci.model.uci".cursor()
local sys = require "luci.sys"
local fs = require "nixio.fs"
local i18n = require "luci.i18n"
local util = require "luci.util"
local support = require "luci.model.cbi.bypass2ray.support"

module("luci.controller.bypass2ray", package.seeall)
appname = require "luci.model.cbi.bypass2ray.support".appname

function index()
    local appname = require "luci.model.cbi.bypass2ray.support".appname
    entry({"admin", "services", appname}, alias("admin", "services", appname, "global"), _("ByPass2Ray"),1).dependent = true
    -- [[ Global Settings ]]
    entry({"admin", "services", appname, "global"}, cbi(appname .. "/global"), _("Global"), 1).leaf = true
    -- [[ Inbound ]]
    entry({"admin", "services", appname, "inbound"},
		arcombine(cbi(appname .. "/inbound"), cbi(appname .. "/inbound_detail")),
		_("Inbound"), 2).leaf = true
    -- [[ Outbound ]]
    entry({"admin", "services", appname, "outbound"},
		arcombine(cbi(appname .. "/outbound"), cbi(appname .. "/outbound_detail")),
		_("Outbound"), 3).leaf = true
    -- [[ Routing ]]
    entry({"admin", "services", appname, "routing"},
		arcombine(cbi(appname .. "/routing"), cbi(appname .. "/routing_detail")),
		_("Routing"), 5).leaf = true
	-- [[ Observatory ]]
	entry({"admin", "services", appname, "observatory"}, cbi(appname .. "/observatory"), _("Observatory"), 15).dependent = true
    -- [[ DNS ]]
    entry({"admin", "services", appname, "dns"},
		arcombine(cbi(appname .. "/dns"), cbi(appname .. "/dns_detail")),
		_("DNS"), 6).leaf = true
    -- [[ Other Settings ]]
    entry({"admin", "services", appname, "others"}, cbi(appname .. "/others"), _("Other Settings"), 20).dependent = true
	-- [[ Config File ]]
	entry({"admin", "services", appname, "config_file"}, cbi(appname .. "/config"), _("Config File"), 40).dependent = true
	-- [[ Log ]]
	entry({"admin", "services", appname, "log"}, cbi(appname .. "/log"), _("Log"), 50).dependent = true
    -- [[ API ]]
    entry({"admin", "services", appname, "connect_status"}, call("connect_status"))
    entry({"admin", "services", appname, "status"}, call("action_status"))
	entry({"admin", "services", appname, "version"}, call("action_version"))
	entry({"admin", "services", appname, "get_bypass2ray_log"}, call("get_bypass2ray_log"))
	entry({"admin", "services", appname, "clear_bypass2ray_log"}, call("clear_bypass2ray_log"))
	entry({"admin", "services", appname, "get_all_log"}, call("get_all_log"))
	entry({"admin", "services", appname, "clear_all_log"}, call("clear_all_log"))
	entry({"admin", "services", appname, "get_access_log"}, call("get_access_log"))
	entry({"admin", "services", appname, "clear_access_log"}, call("clear_access_log"))
	entry({"admin", "services", appname, "get_error_log"}, call("get_error_log"))
	entry({"admin", "services", appname, "clear_error_log"}, call("clear_error_log"))
	entry({"admin", "services", appname, "get_outbound_delay"}, call("get_outbound_delay"))
	--[[ Mod SubScribe ]]
    entry({"admin", "services", appname, "subscribe"}, arcombine(cbi(appname .. "/subscribe"), cbi(appname .. "/subscribe_detail")),
	_("SubScribe"), 100).leaf = true
	entry({"admin", "services", appname, "get_subscribe_peer"}, call("send_subscribe_peer"))
end

function action_status()
	local running = false

	local pid = util.trim(fs.readfile("/var/run/bypass2ray.pid") or "")

	if pid ~= "" then
		local file = uci:get(appname, "global", "binary_file") or "/usr/bin/xray"
		local tmpdir=uci:get(appname, "global", "tmp_dir") or "/tmp/bypass2ray"
		if tmpdir then
			file = tmpdir .. "/" .. file
			if file ~= "" then
				local file_name = fs.basename(file)
				running = sys.call("pidof %s 2>/dev/null | grep -q %s" % { file_name, pid }) == 0
			end
		end
	end

	http.prepare_content("application/json")
	http.write_json({
		running = running
	})
end

function action_version()
	local file = uci:get(appname, "global", "binary_file") or "/usr/bin/xray"

	local info

	if file == "" or not fs.stat(file) then
		info = {
			valid = false,
			message = i18n.translate("Invalid Ray file")
		}
	else
		if not fs.access(file, "rwx", "rx", "rx") then
			fs.chmod(file, 755)
		end

		local version = util.trim(sys.exec("%s version 2>/dev/null | head -n1" % file))

		if version ~= "" then
			info = {
				valid = true,
				version = version
			}
		else
			info = {
				valid = false,
				message = i18n.translate("Can't get Ray version")
			}
		end
	end

	http.prepare_content("application/json")
	http.write_json(info)
end

function connect_status()
	local e = {}
	e.use_time = ""
	local url = luci.http.formvalue("url")
	local result = luci.sys.exec('curl --connect-timeout 3 -o /dev/null -I -skL -w "%{http_code}:%{time_starttransfer}" ' .. url)
	local code = tonumber(luci.sys.exec("echo -n '" .. result .. "' | awk -F ':' '{print $1}'") or "0")
	if code ~= 0 then
		local use_time = luci.sys.exec("echo -n '" .. result .. "' | awk -F ':' '{print $2}'")
		if use_time:find("%.") then
			e.use_time = string.format("%.2f", use_time * 1000)
		else
			e.use_time = string.format("%.2f", use_time / 1000)
		end
		e.ping_type = "curl"
	end
	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end

function get_bypass2ray_log()
	luci.http.write(luci.sys.exec("[ -f '/tmp/bypass2ray.log' ] && cat /tmp/bypass2ray.log"))
end

function clear_bypass2ray_log()
	luci.sys.call("echo -n '' > /tmp/bypass2ray.log")
end

function get_all_log()
	local filename = support.get_all_log_filename()
	local result
	if filename ~= nil then
		result = luci.sys.exec("[ -f '" .. filename .. "' ] && cat " .. filename)
	end
	luci.http.write(result)
end

function clear_all_log()
	local filename = support.get_all_log_filename()
	if filename ~= nil then
		luci.sys.call("echo -n '' > " .. filename)
	end
end

function get_access_log()
	local filename = support.get_access_log_filename()
	local result
	if filename ~= nil then
		result = luci.sys.exec("[ -f '" .. filename .. "' ] && cat " .. filename)
	end
	luci.http.write(result)
end

function clear_access_log()
	local filename = support.get_access_log_filename()
	if filename ~= nil then
		luci.sys.call("echo -n '' > " .. filename)
	end
end

function get_error_log()
	local filename = support.get_error_log_filename()
	local result
	if filename ~= nil then
		result = luci.sys.exec("[ -f '" .. filename .. "' ] && cat " .. filename)
	end
	luci.http.write(result)
end

function clear_error_log()
	local filename = support.get_error_log_filename()
	if filename ~= nil then
		luci.sys.call("echo -n '' > " .. filename)
	end
end

function get_outbound_delay_inside(id)
	local tcping = "sudo -u bypass2ray tcping"
	local cfg = uci:get_all(appname, id)
	local allow_protocol = {"vmess", "vless", "shadowsocks", "socks", "http", "trojan"}
	local inside = false
	local address, port
	for _, v in pairs(allow_protocol) do
		if v == cfg["protocol"] then
			if v == "vmess" then
				address = cfg["settings_vmess_vnext_address"]
				port = cfg["settings_vmess_vnext_port"]
			elseif v == "vless" then
				address = cfg["settings_vless_vnext_address"]
				port = cfg["settings_vless_vnext_port"]
			elseif v == "shadowsocks" then
				address = cfg["settings_shadowsocks_servers_address"]
				port = cfg["settings_shadowsocks_servers_port"]
			elseif v == "socks" then
				address = cfg["settings_socks_servers_address"]
				port = cfg["settings_socks_servers_port"]
			elseif v == "http" then
				address = cfg["settings_http_servers_address"]
				port = cfg["settings_http_servers_port"]
			elseif v == "trojan" then
				address = cfg["settings_trojan_servers_address"]
				port = cfg["settings_trojan_servers_port"]
			end
			inside = true
			break
		end
	end
	if not inside then
		return "-"
	end
	if address == nil or address == "" or port == nil or port == "" then
		return "-"
	end
	if sys.exec("echo -n $(" .. tcping .. " -h >/dev/null 2>&1 || echo 'fail')") == "fail" then
		return "-"
	end
	local pingStr = sys.exec(string.format("echo -n $(" .. tcping .. " -q -c 1 -i 1 -t 2 -p %s %s 2>&1 | grep -o 'time=[0-9].*' | awk -F '=' '{print $2}' | awk '{print $1}') 2>/dev/null", port, address))
	if pingStr == nil or pingStr == "" then
		return "Timeout"
	end
	local ping = tonumber(pingStr)
	if math.floor(ping + 0.5) == 0 then
		ping = 1
	else
		ping = math.floor(ping + 0.5)
	end
	return tostring(ping) .. " ms"
end

function get_outbound_delay()
	local result = get_outbound_delay_inside(luci.http.formvalue("sid"))
	luci.http.write(result)
end

function send_subscribe_peer()
	luci.http.write_json(support.GetSubScribePeerInfo(luci.http.formvalue("sid")))
end