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

if mode == "bstart" then
    local scripts = SearchScript("before_start_script")
    if type(scripts) == "table" then
        if table.getn(scripts) > 0 then
            for _, v in ipairs(scripts) do
                print("Run Before Start Script: [" .. v .. "]")
                sys.call(v)
            end
        else
            print("")
        end
    elseif scripts == -1 then
        print("Fail")
    end
elseif mode == "astart" then
    local scripts = SearchScript("after_start_script")
    if type(scripts) == "table" then
        if table.getn(scripts) > 0 then
            for _, v in ipairs(scripts) do
                print("Run After Start Script: [" .. v .. "]")
                sys.call(v)
            end
        else
            print("")
        end
    elseif scripts == -1 then
        print("Fail")
    end
elseif mode == "bstop" then
    local scripts = SearchScript("before_stop_script")
    if type(scripts) == "table" then
        if table.getn(scripts) > 0 then
            for _, v in ipairs(scripts) do
                print("Run Before Stop Script: [" .. v .. "]")
                sys.call(v)
            end
        else
            print("")
        end
    elseif scripts == -1 then
        print("Fail")
    end
elseif mode == "astop" then
    local scripts = SearchScript("after_stop_script")
    if type(scripts) == "table" then
        if table.getn(scripts) > 0 then
            for _, v in ipairs(scripts) do
                print("Run After Stop Script: [" .. v .. "]")
                sys.call(v)
            end
        else
            print("")
        end
    elseif scripts == -1 then
        print("Fail")
    end
end
