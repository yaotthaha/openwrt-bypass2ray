local dsp = require "luci.dispatcher"
local appname = require "luci.model.cbi.bypass2ray.support".appname
local m, s, o

local uuid = arg[1]

m = Map(appname, "%s - %s" % { translate("ByPass2Ray"), translate("Edit DNS Server") })
m.redirect = dsp.build_url("admin/services/" .. appname .. "/dns")

if m.uci:get(appname, uuid) ~= "dns_server" then
    luci.http.redirect(m.redirect)
	return
end

s = m:section(NamedSection, uuid, "dns_server")
s.anonymous = true
s.addremove = false

easymode = s:option(Flag, "easymode", translate("Easy Mode"))
easymode.default = true

o = s:option(Value, "address", translate("Address"))
o.rmempty = false

o = s:option(Value, "port", translate("Port"))
o.datatype = "and(uinteger, min(0), max(65535))"
o.default = "53"
o:depends({easymode = false})

o = s:option(DynamicList, "domains", translate("Domains"))
o:depends({easymode = false})

o = s:option(DynamicList, "expectips", translate("ExpectIPs"))
o.datatype = "or(ip4addr, ip6addr, ip4prefix, ip6prefix, string)"
o:depends({easymode = false})

return m