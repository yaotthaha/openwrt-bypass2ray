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
	entry({"admin", "services", appname, "get_log"}, call("get_log"))
	entry({"admin", "services", appname, "clear_log"}, call("clear_log"))
	entry({"admin", "services", appname, "get_access_log"}, call("get_access_log"))
	entry({"admin", "services", appname, "get_error_log"}, call("get_error_log"))
    
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

		local version = util.trim(sys.exec("%s --version 2>/dev/null | head -n1" % file))

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

function get_log()
	luci.http.write(luci.sys.exec("[ -f '/tmp/bypass2ray.log' ] && cat /tmp/bypass2ray.log"))
end

function clear_log()
	luci.sys.call("echo '' > /tmp/bypass2ray.log")
end

function get_access_log()
	local filename = support.get_access_log_filename()
	if filename ~= nil then
		local title = "Access Log File: " .. filename .. "<br/>======<br/>"
		luci.http.write(title .. luci.sys.exec("[ -f '" .. filename .. "' ] && cat " .. filename .. " | while read line; do echo $line'<br/>'; done"))
	end
end

function get_error_log()
	local filename = support.get_error_log_filename()
	if filename ~= nil then
		local title = "Error Log File: " .. filename .. "<br/>======<br/>"
		luci.http.write(title .. luci.sys.exec("[ -f '" .. filename .. "' ] && cat " .. filename .. " | while read line; do echo $line'<br/>'; done"))
	end
end