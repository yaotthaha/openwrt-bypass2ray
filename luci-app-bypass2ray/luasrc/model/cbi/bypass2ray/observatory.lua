local support = require "luci.model.cbi.bypass2ray.support"
local uci = require "luci.model.uci".cursor()
local dsp = require "luci.dispatcher"
local jsonc = require 'luci.jsonc'
local appname = support.appname
local m, s, o

function IsExist(appName, type)
	local exist = false
	uci:foreach(appName, type, function (s)
		exist = true
	end)
	return exist
end

if not IsExist(appname, "observatory") then
    uci:add(appname, "observatory")
    uci:commit(appname)
end

m = Map(appname, "%s - %s" % { translate("ByPass2Ray"), translate("Observatory") })

s = m:section(TypedSection, "observatory")
s.anonymous = true
s.addremove = false

o = s:option(Flag, "enable", translate("Enable"))
o.rmempty = false
o.default = false

o = s:option(DynamicList, "subjectselector", translate("SubjectSelector"))
o.rmempty = false
uci:foreach(appname, "outbound", function(t)
	if t["enable"] == "1" then
		if t["tag"] == nil and t["tag"] == "" and t["alias"] == nil and t["alias"] == "" then
			return
		end
		o:value(t["tag"], t["alias"] .. " (" .. t["tag"] .. ")")
	end
end)

o = s:option(Value, "probeurl", translate("probeURL"))

o = s:option(Value, "probeinterval", translate("probeInterval"))

return m
