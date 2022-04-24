local support = require "luci.model.cbi.bypass2ray.support"
local uci = require "luci.model.uci".cursor()
local dsp = require "luci.dispatcher"
local appname = support.appname
local m, s, o

function IsExist(appName, type)
	local exist = false
	uci:foreach(appName, type, function (s)
		exist = true
	end)
	return exist
end

if not IsExist(appname, "dns_global_settings") then
    uci:add(appname, "dns_global_settings")
    uci:commit(appname)
end

m = Map(appname, "%s - %s" % { translate("ByPass2Ray"), translate("DNS") })

s = m:section(TypedSection, "dns_global_settings", translate("DNS Global Settings"))
s.anonymous = true
s.addremove = false

o = s:option(DynamicList, "hosts", translate("Hosts"),
    translate("example: example.com 127.0.0.1"))

o = s:option(Value, "clientip", translate("ClientIP"))
o.datatype = "or(ip4addr, ip6addr)"

o = s:option(ListValue, "querystrategy", translate("QueryStrategy"))
o:value("")
o:value("UseIP")
o:value("UseIPv4")
o:value("UseIPv6")

o = s:option(Flag, "disablecache", translate("DisableCache"))

o = s:option(Flag, "disablefallback", translate("DisableFallback"))

o = s:option(Flag, "disablefallbackifmatch", translate("DisableFallbackIfMatch"))

o = s:option(Value, "tag", translate("Tag"))
o.rmempty = false

---
s = m:section(TypedSection, "dns_server", translate("DNS Servers"))
s.anonymous = true
s.addremove = true
s.sortable = true
s.template = "cbi/tblsection"
s.extedit = dsp.build_url("admin/services/" .. appname .. "/dns/%s")
function s.create(e, t)
    local uuid = support.gen_uuid()
	t = uuid
    TypedSection.create(e, t)
    luci.http.redirect(e.extedit:format(t))
end

o = s:option(DummyValue, "alias", translate("Alias"))
o.cfgvalue = function (...)
	return Value.cfgvalue(...) or "?"
end

o = s:option(Flag, "enable", translate("Enable"))
o.cfgvalue = function (...)
	return Value.cfgvalue(...) or false
end

return m