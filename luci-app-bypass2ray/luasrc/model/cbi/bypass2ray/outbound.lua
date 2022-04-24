
local support = require "luci.model.cbi.bypass2ray.support"
local dsp = require "luci.dispatcher"
local uci = require "luci.model.uci".cursor()
local sys = require "luci.sys"
local appname = "bypass2ray"
local m, s, o

m = Map(appname, "%s - %s" % { translate("ByPass2Ray"), translate("Outbound") })

m:append(Template(appname .. "/outbound_tool"))

s = m:section(TypedSection, "outbound")
s.anonymous = true
s.addremove = true
s.sortable = true
s.template = "cbi/tblsection"
s.extedit = dsp.build_url("admin/services/" .. appname .. "/outbound/%s")
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

o = s:option(DummyValue, "subscribe_tag", translate("SubscribeAlias"))
o.cfgvalue = function(_, n)
	local Value = uci:get(appname, n, "subscribe_tag")
	local ReturnV = "-"
	if Value ~= nil and Value ~= "" then
		local Sub = uci:get(appname, Value, "alias")
		if Sub ~= nil and Sub ~= "" then
			ReturnV = Sub
		end
	end
	return ReturnV
end

o = s:option(DummyValue, "protocol", translate("Protocol"))
o.cfgvalue = function (...)
	return Value.cfgvalue(...) or "?"
end

--[[
o = s:option(DummyValue, "tag", translate("Tag"))
o.cfgvalue = function (...)
	return Value.cfgvalue(...) or "-"
end
--]]

o = s:option(DummyValue, "ps_tag", translate("Proxy Tag"))
o.cfgvalue = function (...)
	return Value.cfgvalue(...) or "-"
end


o = s:option(Flag, "enable", translate("Enable"))
o.cfgvalue = function (...)
	return Value.cfgvalue(...) or false
end

o = s:option(DummyValue, "_delay", translate("Delay"))

m:append(Template(appname .. "/test_outbound_time"))

return m