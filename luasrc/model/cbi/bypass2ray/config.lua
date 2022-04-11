local uci = require "luci.model.uci".cursor()
local util = require "luci.util"
local fs = require "nixio.fs"
local support = require "luci.model.cbi.bypass2ray.support"
local appname = support.appname

local config_file = uci:get(appname, "global", "config_file")

if not config_file or util.trim(config_file) == "" then
	config_file = "/tmp/bypass2ray/" .. appname .. "_run.json"
end

local config_content = fs.readfile(config_file) or translate("Failed to open file.")

local m

m = SimpleForm(appname, "%s - %s" % { translate("ByPass2Ray"), translate("Config") },
	"<p>%s</p><p>%s</p>" % {
		translatef("Config File: %s", config_file),
		"<pre style=\"-moz-tab-size: 4;-o-tab-size: 4;tab-size: 4;word-break: break-all;\">%s</pre>" % config_content,
	})

m.reset = false
m.submit = false

return m