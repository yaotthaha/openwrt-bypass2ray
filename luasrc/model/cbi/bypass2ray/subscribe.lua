
local sys = require "luci.sys"
local dsp = require "luci.dispatcher"
local support = require "luci.model.cbi.bypass2ray.support"
local uci = require "luci.model.uci".cursor()
local appname = support.appname

m = Map(appname, "%s - %s" % { translate("ByPass2Ray"), translate("SubScribe") })

s = m:section(TypedSection, "subscribe")
s.anonymous = true
s.addremove = true
s.sortable = true
s.template = "cbi/tblsection"
s.extedit = dsp.build_url("admin/services/" .. appname .. "/subscribe/%s")
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

o = s:option(Button, "_update", translate("Update"))
o.inputstyle = "save"
function o.write(t, n)
    sys.call("lua /usr/share/bypass2ray/subscribe_update.lua " .. n .. " >/dev/null 2>&1 &")
end

o = s:option(Button, "_delete_all", translate("Delete All Peers(Outbounds)"))
o.inputstyle = "reset"
function o.write(t, n)
    uci:foreach(appname, "outbound", function(s)
        if s["subscribe_tag"] == n then
            uci:delete(appname, s[".name"])
        end
    end)
    uci:commit(appname)
end

o = s:option(Button, "_delete_list", translate("Delete Peer List"))
o.inputstyle = "reset"
function o.write(t, n)
    uci:delete(appname, n, "peerlist")
    uci:commit(appname)
end

return m