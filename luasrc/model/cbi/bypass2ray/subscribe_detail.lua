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
local shell_default = "curl -kfsSL '::url::' --user-agent 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.122 Safari/537.36' --retry 3 --connect-timeout 3"
o.placeholder = shell_default
o.default = shell_default

s:option(DynamicList, "include", translate("Include"), translate("Support Regexp"))

s:option(DynamicList, "exclude", translate("Exclude"), translate("Support Regexp"))

o = s:option(ListValue, "mode", translate("Match Mode"))
o:value("1", translate("Include --> Exclude"))
o:value("2", translate("Exclude --> Include"))
o.default = "1"

m:append(Template(appname .. "/subscribe_list"))

return m