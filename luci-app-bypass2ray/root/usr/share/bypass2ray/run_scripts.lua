#!/usr/bin/lua
local support = require "luci.model.cbi.bypass2ray.support"
local uci = require "luci.model.uci".cursor()
local sys = require "luci.sys"
local appname = support.appname

local mode = arg[1]

function SearchScript(name)
    local cfg
    uci:foreach(appname, "other_settings_scripts", function (s)
        if type(s[name]) == "table" then
            cfg = s[name]
        else
            return -1
        end
    end)
    return cfg
end

if mode == "prestart" then
    local scripts = SearchScript("pre_start_script")
    if type(scripts) == "table" then
        if table.getn(scripts) > 0 then
            for _, v in ipairs(scripts) do
                print("Run Pre Start Script: [" .. v .. "]")
                sys.call(v)
            end
        else
            print("")
        end
    elseif scripts == -1 then
        print("Fail")
    end
elseif mode == "poststart" then
    local scripts = SearchScript("post_start_script")
    if type(scripts) == "table" then
        if table.getn(scripts) > 0 then
            for _, v in ipairs(scripts) do
                print("Run Post Start Script: [" .. v .. "]")
                sys.call(v)
            end
        else
            print("")
        end
    elseif scripts == -1 then
        print("Fail")
    end
elseif mode == "prestop" then
    local scripts = SearchScript("pre_stop_script")
    if type(scripts) == "table" then
        if table.getn(scripts) > 0 then
            for _, v in ipairs(scripts) do
                print("Run Pre Stop Script: [" .. v .. "]")
                sys.call(v)
            end
        else
            print("")
        end
    elseif scripts == -1 then
        print("Fail")
    end
elseif mode == "poststop" then
    local scripts = SearchScript("post_stop_script")
    if type(scripts) == "table" then
        if table.getn(scripts) > 0 then
            for _, v in ipairs(scripts) do
                print("Run Post Stop Script: [" .. v .. "]")
                sys.call(v)
            end
        else
            print("")
        end
    elseif scripts == -1 then
        print("Fail")
    end
end
