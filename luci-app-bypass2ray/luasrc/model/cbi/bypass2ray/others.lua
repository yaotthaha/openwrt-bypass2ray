local support = require "luci.model.cbi.bypass2ray.support"
local uci = require "luci.model.uci".cursor()
local sys = require "luci.sys"
local appname = support.appname
local m, s

function IsExist(appName, type)
	local exist = false
	uci:foreach(appName, type, function (s)
		exist = true
	end)
	return exist
end

if not IsExist(appname, "other_settings_scripts") then
    uci:add(appname, "other_settings_scripts")
    uci:commit(appname)
end

m = Map(appname, "%s - %s" % { translate("ByPass2Ray"), translate("Other Settings") })

m:append(Template(appname .. "/other_tips"))

s = m:section(TypedSection, "other_settings_scripts", translate("Scripts"))
s.anonymous = true
s.addremove = false

s:option(DynamicList, "pre_start_script", translate("Pre Start Scripts"))

s:option(DynamicList, "post_start_script", translate("Post Start Scripts"))

s:option(DynamicList, "pre_stop_script", translate("Pre Stop Scripts"))

s:option(DynamicList, "post_stop_script", translate("Post Stop Scripts"))

s = m:section(TypedSection, "geofile", translate("Geo File"))
s.anonymous = true
s.addremove = false

o = s:option(DummyValue, "_geoip_file_check", translate("GeoIP"))
o.cfgvalue = function(...)
	local msg = sys.exec("echo -n $(ls -lah --full-time /usr/share/bypass2ray/geoip.dat 2>/dev/null | awk '{print $5\"|\"$6\" \"$7}')")
	if msg == "" then
		return translate("File Not Found")
	end
	local msg_table = support.split(msg, "|")
	return string.format("%s: %s %s: %s", translate("File Size"), msg_table[1], translate("Update Time"), msg_table[2])
end

o = s:option(DummyValue, "_geosite_file_check", translate("GeoSite"))
o.cfgvalue = function(...)
	local msg = sys.exec("echo -n $(ls -lah --full-time /usr/share/bypass2ray/geosite.dat 2>/dev/null | awk '{print $5\"|\"$6\" \"$7}')")
	if msg == "" then
		return translate("File Not Found")
	end
	local msg_table = support.split(msg, "|")
	return string.format("%s: %s %s: %s", translate("File Size"), msg_table[1], translate("Update Time"), msg_table[2])
end

o = s:option(Button, "_update", translate("Update"))
o.inputstyle = "start"
o.write = function ()
	sys.call("lua /usr/share/" .. appname .. "/geoupdate.lua >/dev/null 2>&1 &")
end

return m