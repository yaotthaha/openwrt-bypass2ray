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

if not IsExist(appname, "routing_global_settings") then
    uci:add(appname, "routing_global_settings")
    uci:commit(appname)
end

m = Map(appname, "%s - %s" % { translate("ByPass2Ray"), translate("Routing") })

s = m:section(TypedSection, "routing_global_settings", translate("Routing Global Settings"))
s.anonymous = true
s.addremove = false

o = s:option(ListValue, "domainstrategy", translate("DomainStrategy"))
o:value("")
o:value("AsIs")
o:value("IPIfNonMatch")
o:value("IPOnDemand")

-- Rule

s = m:section(TypedSection, "routing_rule", translate("Rule"))
s.anonymous = true
s.addremove = true
s.sortable = true
s.template = "cbi/tblsection"
s.extedit = dsp.build_url("admin/services/" .. appname .. "/routing/%s")
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

-- Balancer

s = m:section(TypedSection, "routing_balancer", translate("Balancer"))
s.anonymous = true
s.addremove = true
s.sortable = true
s.template = "cbi/tblsection"
s.extedit = dsp.build_url("admin/services/" .. appname .. "/routing/%s")
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

o = s:option(DummyValue, "tag", translate("Tag"))
o.cfgvalue = function (...)
	return Value.cfgvalue(...) or "?"
end

return m