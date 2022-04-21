local dsp = require "luci.dispatcher"
local uci = require "luci.model.uci".cursor()
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
	uci:foreach(appname, "inbound", function(t)
		if t["enable"] == "1" then
			if t["tag"] == nil and t["tag"] == "" and t["alias"] == nil and t["alias"] == "" then
				return
			end
			o:value(t["tag"], t["alias"] .. " (" .. t["tag"] .. ")")
		end
	end)

	o = s:option(MultiValue, "protocol", translate("Protocol"))
	o:value("http")
	o:value("tls")
	o:value("bittorrent")

	o = s:option(Value, "attrs", translate("Attrs"))

	o = s:option(ListValue, "outboundtag", translate("OutboundTag"))
	o:value("")
	uci:foreach(appname, "outbound", function(t)
		if t["enable"] == "1" then
			if t["tag"] == nil and t["tag"] == "" and t["alias"] == nil and t["alias"] == "" then
				return
			end
			o:value(t["tag"], t["alias"] .. " (" .. t["tag"] .. ")")
		end
	end)

	o = s:option(ListValue, "balancertag", translate("BalancerTag"))
	o:value("")
	uci:foreach(appname, "routing_balancer", function(t)
		if t["enable"] == "1" then
			if t["tag"] == nil and t["tag"] == "" and t["alias"] == nil and t["alias"] == "" then
				return
			end
			o:value(t["tag"], t["alias"] .. " (" .. t["tag"] .. ")")
		end
	end)

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
	uci:foreach(appname, "outbound", function(t)
		if t["enable"] == "1" then
			if t["tag"] == nil and t["tag"] == "" and t["alias"] == nil and t["alias"] == "" then
				return
			end
			o:value(t["tag"], t["alias"] .. " (" .. t["tag"] .. ")")
		end
	end)

	o = s:option(ListValue, "strategy_type", translate("Strategy Type"))
	o:value("random")
	o:value("leastPing")

	return m
else
	luci.http.redirect(m.redirect)
	return
end