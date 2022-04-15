local dsp = require "luci.dispatcher"
local appname = require "luci.model.cbi.bypass2ray.support".appname
local m, s, o

local uuid = arg[1]

m = Map(appname, "%s - %s" % { translate("ByPass2Ray"), translate("Edit SubScribe") })
m.redirect = dsp.build_url("admin", "services", appname, "subscribe")

if m.uci:get(appname, uuid) ~= "subscribe" then
	luci.http.redirect(m.redirect)
	return
end

s = m:section(NamedSection, uuid, "subscribe")
s.anonymous = true
s.addremove = false

o = s:option(Value, "alias", translate("Alias"))
o.rmempty = false

o = s:option(Value, "url", translate("URL"))
o.datatype = "string"

o = s:option(Value, "shell", translate("Shell"), translate("Use `::url::` Instead $URL"))
local shell_default = "curl -kfsSL '::url::' --user-agent '\'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.122 Safari/537.36\'' --retry 3 --connect-timeout 3 --max-time 30"
o.placeholder = shell_default
o.default = shell_default

s:option(DynamicList, "include", translate("Include"))

s:option(DynamicList, "exclude", translate("Exclude"))

o = s:option(ListValue, "mode", translate("Match Mode"))
o:value("1", translate("Include --> Exclude"))
o:value("2", translate("Exclude --> Include"))
o.default = "1"

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

m:append(Template(appname .. "/subscribe_list"))

return m