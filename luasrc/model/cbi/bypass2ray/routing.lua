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

o = s:option(DummyValue, "inboundtag", translate("Inbound Alias"))
o.cfgvalue = function (_, n)
	local Value = uci:get_list(appname, n, "inboundtag")
	if Value == nil or table.getn(Value) <= 0 then
		return "-"
	end
	local R = {}
	for _, v in pairs(Value) do
		local V
		uci:foreach(appname, "inbound", function(s)
			if s["tag"] == nil or s["tag"] ~= v then
				return
			end
			if s["alias"] ~= nil and s["alias"] ~= "" then
				V = s["alias"]
			else
				V = "?"
			end
		end)
		if V == nil or V == "" then
			table.insert(R, "-")
		else
			table.insert(R, V)
		end
	end
	return jsonc.stringify(R, 1)
end

o = s:option(DummyValue, "outboundtag", translate("Outbound Alias"))
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
end

o = s:option(DummyValue, "balancertag", translate("BalancerAlias"))
o.cfgvalue = function (_, n)
	local Value = uci:get(appname, n, "balancertag")
	if Value == nil or Value == "" then
		return "-"
	end
	local V
	uci:foreach(appname, "routing_balancer", function(s)
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

o = s:option(DummyValue, "selector", translate("Selector"))
o.cfgvalue = function (_, n)
	local Value = uci:get(appname, n, "selector")
	if type(Value) == "table" or table.getn(Value) <= 0 then
		local S = {}
		uci:foreach(appname, "outbound", function(s)
			for _, V in ipairs(Value) do
				if s["tag"] == V then
					table.insert(S, s["alias"])
				end
			end
		end)
		return jsonc.stringify(S, 1)
	else
		return "-"
	end
end

return m