local uci = require "luci.model.uci".cursor()
local sys = require "luci.sys"
local appname = require "luci.model.cbi.bypass2ray.support".appname

function IsExist(appName, type)
	local exist = false
	uci:foreach(appName, type, function (s)
		exist = true
	end)
	return exist
end

if not IsExist(appname, "global") then
    uci:add(appname, "global")
    uci:commit(appname)
end

m = Map(appname, "%s - %s" % { translate("ByPass2Ray"), translate("Global") })

m:append(Template(appname .. "/connect_status"))

m:append(Template(appname .. "/status_header"))

s = m:section(NamedSection, "global", "global")
s.addremove = false
s.anonymos = true

o = s:option(Flag, "enable", translate("Enable"))
o.default = 0

o = s:option(Button, "_start", translate("Start Service"))
o.inputstyle = "start"
o.write = function ()
	sys.call("/etc/init.d/" .. appname .. " start 2>/dev/null")
end

o = s:option(Button, "_stop", translate("Stop Service"))
o.inputstyle = "stop"
o.write = function ()
	sys.call("/etc/init.d/" .. appname .. " stop 2>/dev/null")
end

o = s:option(Button, "_restart", translate("Restart Service"))
o.inputstyle = "restart"
o.write = function ()
	sys.call("/etc/init.d/" .. appname .. " restart 2>/dev/null")
end

o = s:option(Value, "binary_file", translate("Ray file"), "<em>%s</em>" % translate("Collecting data..."))
o.datatype = "file"
o.placeholder = "/usr/bin/xray"
o.default = "/usr/bin/xray"

o = s:option(Value, "resource_location", translate("Resource Location"))
o.datatype = "directory"
o.placeholder = "/usr/share/bypass2ray/"
o.default = "/usr/share/bypass2ray/"

o = s:option(Value, "tmp_dir", translate("Temp Dir"))
o.placeholder = "/tmp/bypass2ray"
o.default = "/tmp/bypass2ray"

o = s:option(Value, "config_file", translate("Custom Config file"), translate("Use custom config file."))
o.datatype = "file"
o:value("", translate("None"))

o = s:option(Value, "access_log", translate("Access log file"))
o:depends("config_file", "")
o:value("/dev/null")
o:value("/tmp/bypass2ray/bypass2ray_access.log")
o:value("/var/log/bypass2ray_access.log")

o = s:option(ListValue, "loglevel", translate("Log level"))
o:depends("config_file", "")
o:value("debug", translate("Debug"))
o:value("info", translate("Info"))
o:value("warning", translate("Warning"))
o:value("error", translate("Error"))
o:value("none", translate("None"))
o.default = "warning"

o = s:option(Value, "error_log", translate("Error log file"))
o:depends("config_file", "")
o:depends("loglevel", "debug")
o:depends("loglevel", "info")
o:depends("loglevel", "warning")
o:depends("loglevel", "error")
o:value("/dev/null")
o:value("/tmp/bypass2ray/bypass2ray_error.log")
o:value("/var/log/bypass2ray_error.log")

o = s:option(Flag, "dns_log", translate("DNS Log"))

local apply = luci.http.formvalue("cbi.apply")
if apply then
	luci.sys.exec("/etc/init.d/" .. appname .. " restart")
end

return m