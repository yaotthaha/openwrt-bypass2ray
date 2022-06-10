#!/usr/bin/lua

local sys = require "luci.sys"
local jsonc = require "luci.jsonc"

local restart = arg[1]
local TEMPDIR = "/tmp/geodir"
local ResourceDIR = "/usr/share/bypass2ray"
--local logtofile = "/tmp/geoupdate.log"
local logtofile = "/tmp/bypass2ray.log"

local geosite_url = "https://raw.githubusercontent.com/yaotthaha/v2ray-rules-dat/release/geosite.dat"
local geosite_sha256sum_url = "https://raw.githubusercontent.com/yaotthaha/v2ray-rules-dat/release/geosite.dat.sha256sum"
local geoip_url = "https://raw.githubusercontent.com/yaotthaha/geoip/release/geoip.dat"
local geoip_sha256sum_url = "https://raw.githubusercontent.com/yaotthaha/geoip/release/geoip.dat.sha256sum"
local cnip_url = "https://raw.githubusercontent.com/yaotthaha/geoip/release/text/cn.txt"

local function Log(...)
    print(...)
    if logtofile ~= "" then
        sys.exec('echo "[`date +"%Y-%m-%d %H:%M:%S"`] ' .. ... .. '" >> ' .. logtofile)
    end
end

local function ResolveIP(domain)
    if domain == nil or domain == "" then
        return -1
    end
    local httpdnsurl = "https://223.5.5.5/resolve?name=" .. domain .. "&short=1"
    local rt = sys.exec("echo -n $(curl -fsSLk --retry 3 --connect-timeout 3 --max-time 30 '" .. httpdnsurl .. "' 2>/dev/null)")
    if rt == nil or rt == "" then
        return -1
    end
    local resolveIP = jsonc.parse(rt)
    if type(resolveIP) ~= "table" then
        return -2
    end
    if #resolveIP <= 0 then
        return -3
    end
    return resolveIP[1]
end

local function DownloadAndSaveFile(url, filename)
    local ghproxyDomain = "ghproxy.com"
    local IP = ResolveIP(ghproxyDomain)
    if IP == -1 or IP == -2 or IP == -3 then
        return -1
    end
    local cmd = "curl -fsSLk --retry 3 --connect-timeout 3 --max-time 30 --resolve '" .. ghproxyDomain .. ":443:" .. IP .. "' 'https://" .. ghproxyDomain .. "/" .. url .. "' --output " .. filename .. " >/dev/null 2>&1; echo $?"
    local rt = sys.exec("echo -n $(" .. cmd .. ")")
    Log(rt)
    if rt ~= "0" then
        return -2
    end
    return 0
end

local function GeoFileCompare(datfile, sumfile)
    local rt = sys.exec('if [ "$(sha256sum ' .. datfile .. ' | awk \'{Log $1}\')" = "$(cat ' .. sumfile .. ' | awk \'{Log $1}\')" ]; then echo -n 0; else echo -n 1; fi')
    if rt == "1" then
        return 1
    elseif rt == "0" then
        return 0
    else
        return -1
    end
end

local function Prepare()
    sys.exec('if [ ! -d "' .. TEMPDIR .. '" ]; then mkdir -p ' .. TEMPDIR .. '; else rm -rf ' .. TEMPDIR .. '/*; fi')
    sys.exec('chmod 0777 ' .. TEMPDIR .. ' -R')
end

local function Clean()
    sys.exec('if [ -d "' .. TEMPDIR .. '" ]; then rm -rf ' .. TEMPDIR .. '; fi')
end

local function Update()
    if TEMPDIR == nil or TEMPDIR == "" then
        return -1
    end
    Prepare()
    --
    local geosite_replace, geoip_replace
    --
    local rt1 = DownloadAndSaveFile(geosite_url, TEMPDIR .. "/geosite.dat")
    if rt1 ~= 0 then
        Log("Fail to Download geosite.dat")
        Clean()
        return -1
    end
    local rt2 = DownloadAndSaveFile(geosite_sha256sum_url, TEMPDIR .. "/geosite.dat.sha256sum")
    if rt2 ~= 0 then
        Log("Fail to Download geosite.dat.sha256sum")
        Clean()
        return -1
    end
    local compare1 = GeoFileCompare(TEMPDIR .. "/geosite.dat", TEMPDIR .. "/geosite.dat.sha256sum")
    if compare1 == -1 then
        Log("Fail to compare geosite.dat")
        Clean()
        return -1
    elseif compare1 == 0 then
        geosite_replace = true
    elseif compare1 == 1 then
        geosite_replace = false
    end
    if geosite_replace then
        sys.exec("mv " .. TEMPDIR .. "/geosite.dat" .. " " .. ResourceDIR .. "/geosite.dat")
        Log("Success Replace geosite.dat")
    end
    local rt3 = DownloadAndSaveFile(geoip_url, TEMPDIR .. "/geoip.dat")
    if rt3 ~= 0 then
        Log("Fail to Download geoip.dat")
        Clean()
        return -1
    end
    local rt4 = DownloadAndSaveFile(geoip_sha256sum_url, TEMPDIR .. "/geoip.dat.sha256sum")
    if rt4 ~= 0 then
        Log("Fail to Download geoip.dat.sha256sum")
        Clean()
        return -1
    end
    local compare2 = GeoFileCompare(TEMPDIR .. "/geoip.dat", TEMPDIR .. "/geoip.dat.sha256sum")
    if compare2 == -1 then
        Log("Fail to compare geoip.dat")
        Clean()
        return -1
    elseif compare2 == 0 then
        geoip_replace = true
    elseif compare2 == 1 then
        geoip_replace = false
    end
    if geoip_replace then
        sys.exec("mv " .. TEMPDIR .. "/geoip.dat" .. " " .. ResourceDIR .. "/geoip.dat")
        Log("Success Replace geoip.dat")
    end
    local rt5 = DownloadAndSaveFile(cnip_url, TEMPDIR .. "/cnip.txt")
    if rt5 ~= 0 then
        Log("Fail to Download cnip.txt")
        Clean()
        return -1
    else
        sys.exec("mv " .. TEMPDIR .. "/cnip.txt" .. " " .. ResourceDIR .. "/cnip.txt")
        Log("Success Replace cnip.txt")
    end
    Log("Success!!!")
    Clean()
    return 0
end


Log("=== Start Update GeoFile ===")
if Update() ~= 0 then
    Log("=== Stop Update GeoFile ===")
    return -1
else
    if restart ~= nil and restart ~= "" then
        Log("Restart ByPass2Ray")
        sys.call("/etc/init.d/bypass2ray restart")
    end
    Log("=== Stop Update GeoFile ===")
end