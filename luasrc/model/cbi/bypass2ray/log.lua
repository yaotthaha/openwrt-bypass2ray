local support = require "luci.model.cbi.bypass2ray.support"
local appname = support.appname
local m

m = SimpleForm(appname, "%s - %s" % { translate("ByPass2Ray"), translate("Log") })
m.reset = false
m.submit = false
m:append(Template(appname .. "/log"))

return m