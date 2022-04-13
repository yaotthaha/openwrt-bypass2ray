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

o = s:option(DummyValue, "inboundtag", translate("Inbound Tag"))
o.cfgvalue = function (_, n)
	local Value = uci:get(appname, n, "inboundtag")
	if type(Value) == "table" then
		if table.getn(Value) <= 0 then
			return "-"
		end
		local str = ""
		for K, V in ipairs(Value) do
			if K == table.getn(Value) then
				str = str .. V
			else
				str = str .. V .. ", "
			end
		end
		return str
	else
		return "-"
	end
end

o = s:option(DummyValue, "outboundtag", translate("Outbound Tag"))
o.cfgvalue = function (_, n)
	local Value = uci:get(appname, n, "outboundtag")
	if Value == nil or Value == "" then
		return "-"
	end
	local V
	uci:foreach(appname, "outbound", function(s)
		if s["tag"] == nil or s["tag"] ~= Value then
			return
		end
		if s["alias"] ~= nil and s["alias"] ~= "" then
			V = s["alias"]
		else
			V = "?"
		end
	end)
	if V == nil or V == "" then
		return "-"
	else
		return V
	end
	--[[
	if type(Value) == "table" then
		if table.getn(Value) <= 0 then
			return "-"
		end
		local str = ""
		for K, V in ipairs(Value) do
			if K == table.getn(Value) then
				str = str .. V
			else
				str = str .. V .. ", "
			end
		end
		return str
	else
		return "-"
	end
	--]]
end

o = s:option(DummyValue, "balancertag", translate("Balancer Tag"))
o.cfgvalue = function (...)
	return Value.cfgvalue(...) or "-"
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

o = s:option(DummyValue, "selector", translate("Selector"))
o.cfgvalue = function (_, n)
	local Value = uci:get(appname, n, "selector")
	if type(Value) == "table" then
		if table.getn(Value) <= 0 then
			return "-"
		end
		local str = ""
		for K, V in ipairs(Value) do
			if K == table.getn(Value) then
				str = str .. V
			else
				str = str .. V .. ", "
			end
		end
		return str
	else
		return "-"
	end
end

return m