local support = require "luci.model.cbi.bypass2ray.support"
local uci = require "luci.model.uci".cursor()
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

s = m:section(TypedSection, "other_settings_scripts", translate("Scripts"))
s.anonymous = true
s.addremove = false

s:option(DynamicList, "before_start_script", translate("Before Start Scripts"))

s:option(DynamicList, "before_stop_script", translate("Before Stop Scripts"))

s:option(DynamicList, "after_start_script", translate("After Start Scripts"))

s:option(DynamicList, "after_stop_script", translate("After Stop Scripts"))

return m