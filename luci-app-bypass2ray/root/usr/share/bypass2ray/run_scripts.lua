#!/usr/bin/lua
local support = require "luci.model.cbi.bypass2ray.support"
local uci = require "luci.model.uci".cursor()
local sys = require "luci.sys"
local appname = support.appname
local jsonc = require 'luci.jsonc'

local mode = arg[1]
local savefilename = "/tmp/bypass2ray/stop_run_script.json"

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
elseif mode == "savestop" then
    local pre_stop_script = SearchScript("pre_stop_script")
    local post_stop_script = SearchScript("post_stop_script")
    local t = {}
    t["pre_stop_script"] = pre_stop_script
    t["post_stop_script"] = post_stop_script
    local tjson = jsonc.stringify(t, 1)
    local sf = io.open(savefilename, "w")
    sf:write(tjson)
    sf:close()
elseif mode == "prestop" then
    local d = ""
    sf = io.open(savefilename ,"r")
    for line in sf:lines() do
	    d = d .. line .. "\n"
    end
    sf:close()
    local dtable = jsonc.parse(d)
    local scripts = dtable["pre_stop_script"]
    if type(scripts) == "table" then
        if table.getn(scripts) > 0 then
            for _, v in ipairs(scripts) do
                print("Run Pre Stop Script: [" .. v .. "]")
                sys.call(v)
            end
        else
            print("")
        end
    elseif scripts == nil then
        return
    elseif scripts == -1 then
        print("Fail")
    end
elseif mode == "poststop" then
    local d = ""
    sf = io.open(savefilename ,"r")
    for line in sf:lines() do
	    d = d .. line .. "\n"
    end
    sf:close()
    local dtable = jsonc.parse(d)
    local scripts = dtable["post_stop_script"]
    if type(scripts) == "table" then
        if table.getn(scripts) > 0 then
            for _, v in ipairs(scripts) do
                print("Run Post Stop Script: [" .. v .. "]")
                sys.call(v)
            end
        else
            print("")
        end
    elseif scripts == nil then
        return
    elseif scripts == -1 then
        print("Fail")
    end
end
