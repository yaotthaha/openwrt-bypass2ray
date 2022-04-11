local dsp = require "luci.dispatcher"
local appname = require "luci.model.cbi.bypass2ray.support".appname
local m, s, o

local uuid = arg[1]

m = Map(appname, "%s - %s" % { translate("ByPass2Ray"), translate("Edit Routing") })
m.redirect = dsp.build_url("admin/services/" .. appname .. "/routing")

if m.uci:get(appname, uuid) == "routing_rule" then
	s = m:section(NamedSection, uuid, "routing_rule", translate("Rule"))
	s.anonymous = true
	s.addremove = false

	o = s:option(Value, "alias", translate("Alias"))
	o.rmempty = false

	o = s:option(Flag, "enable", translate("Enable"))
	o.default = false

	o = s:option(ListValue, "type", translate("Type"))
	o:value("field")
	o.default = "field"

	o = s:option(DynamicList, "domain", translate("Domain"))

	o = s:option(DynamicList, "ip", translate("IP"))
	o.datatype = "or(ip4addr, ip6addr, ip4prefix, ip6prefix, string)"

	o = s:option(DynamicList, "port", translate("Port"))
	o.datatype = "or(port, portrange)"

	o = s:option(DynamicList, "sourceport", translate("SourcePort"))
	o.datatype = "or(port, portrange)"

	o = s:option(MultiValue, "network", translate("Network"))
	o:value("tcp", translate("TCP"))
	o:value("udp", translate("UDP"))

	o = s:option(DynamicList, "source", translate("Source"))
	o.datatype = "or(ip4addr, ip6addr, ip4prefix, ip6prefix, string)"

	o = s:option(DynamicList, "inboundtag", translate("InboundTag"))

	o = s:option(MultiValue, "protocol", translate("Protocol"))
	o:value("http")
	o:value("tls")
	o:value("bittorrent")

	o = s:option(Value, "attrs", translate("Attrs"))

	o = s:option(Value, "outboundtag", translate("OutboundTag"))

	o = s:option(Value, "balancertag", translate("BalancerTag"))

	return m
elseif m.uci:get(appname, uuid) == "routing_balancer" then
	s = m:section(NamedSection, uuid, "routing_balancer", translate("Balancer"))
	s.anonymous = true
	s.addremove = false

	o = s:option(Value, "alias", translate("Alias"))
	o.rmempty = false

	o = s:option(Flag, "enable", translate("Enable"))
	o.default = false

	o = s:option(Value, "tag", translate("Tag"))
	o.rmempty = false

	o = s:option(DynamicList, "selector", translate("Selector"))
	o.rmempty = false

	return m
else
	luci.http.redirect(m.redirect)
	return
end