module("luci.model.cbi.bypass2ray.support", package.seeall)
local sys = require "luci.sys"
local uci = require "luci.model.uci".cursor()

appname = "bypass2ray"

function gen_uuid(format)
    local uuid = sys.exec("echo -n $(cat /proc/sys/kernel/random/uuid)")
    if format == nil then
        uuid = string.gsub(uuid, "-", "")
    end
    return uuid
end

function url(...)
    local url = string.format("admin/services/%s", appname)
    local args = { ... }
    for i, v in pairs(args) do
        if v ~= "" then
            url = url .. "/" .. v
        end
    end
    return require "luci.dispatcher".build_url(url)
end

function get_access_log_filename()
    local access_log = uci:get(appname, "global", "access_log")
    if access_log ~= nil and access_log ~= "" and access_log ~= "/dev/null" then
        local exist = luci.sys.exec("ls " .. access_log .. " 2>/dev/null")
        if exist == "" then
            return nil
        end
        return access_log
    else
        return nil
    end
end

function get_error_log_filename()
    local error_log = uci:get(appname, "global", "error_log")
    if error_log ~= nil and error_log ~= "" and error_log ~= "/dev/null" then
        local exist = luci.sys.exec("ls " .. error_log .. " 2>/dev/null")
        if exist == "" then
            return nil
        end
        return error_log
    else
        return nil
    end
end