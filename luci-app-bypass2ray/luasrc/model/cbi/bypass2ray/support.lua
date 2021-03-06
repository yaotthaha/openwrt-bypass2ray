module("luci.model.cbi.bypass2ray.support", package.seeall)
local sys = require "luci.sys"
local uci = require "luci.model.uci".cursor()

appname = "bypass2ray"
ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36 Edg/100.0.1185.50"

function gen_uuid(len)
    local uuid = sys.exec("echo -n $(cat /proc/sys/kernel/random/uuid)")
    uuid = string.gsub(uuid, "-", "")
    if len ~= nil and len < 32 and len > 1 then
        uuid = string.sub(uuid, 1, len)
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

function get_all_log_filename()
    local tempdir = uci:get(appname, "global", "tmp_dir") or "/tmp/bypass2ray"
    if tempdir ~= nil and tempdir ~= "" then
        local exist = luci.sys.exec("ls " .. tempdir .. "/all.log" .. " 2>/dev/null")
        if exist == "" then
            return nil
        end
        return tempdir .. "/all.log"
    else
        return nil
    end
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

function base64Encode(data)
    local b='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    return ((data:gsub('.', function(x)
        local r,b='',x:byte()
        for i=8,1,-1 do r=r..(b%2^i-b%2^(i-1)>0 and '1' or '0') end
        return r;
    end)..'0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
        if (#x < 6) then return '' end
        local c=0
        for i=1,6 do c=c+(x:sub(i,i)=='1' and 2^(6-i) or 0) end
        return b:sub(c+1,c+1)
    end)..({ '', '==', '=' })[#data%3+1])
end

function base64Decode(data)
    local b='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    data = string.gsub(data, '[^'..b..'=]', '')
    return (data:gsub('.', function(x)
        if (x == '=') then return '' end
        local r,f='',(b:find(x)-1)
        for i=6,1,-1 do r=r..(f%2^i-f%2^(i-1)>0 and '1' or '0') end
        return r;
    end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
        if (#x ~= 8) then return '' end
        local c=0
        for i=1,8 do c=c+(x:sub(i,i)=='1' and 2^(8-i) or 0) end
            return string.char(c)
    end))
end

function split(str, d)
	local lst = { }
	local n = string.len(str)
	local start = 1
	while start <= n do
		local i = string.find(str, d, start) -- find 'next' 0
		if i == nil then
			table.insert(lst, string.sub(str, start, n))
			break
		end
		table.insert(lst, string.sub(str, start, i-1))
		if i == n then
			table.insert(lst, "")
			break
		end
		start = i + 1
	end
	return lst
end

function LogToFile(...)
    sys.call("echo `date +\"[%Y-%m-%d %H:%M:%S]\"`" .. ... .. " >> /tmp/" .. appname .. ".log")
end

function GetSubScribePeerInfo(sid)
    local All = {}
    uci:foreach(appname, "outbound", function(s)
        if s["subscribe_tag"] == nil or s["subscribe_tag"] ~= sid then
            return
        end
        local StrSlice = {}
        StrSlice["alias"] = s["alias"]
        StrSlice["type"] = s["protocol"]
        StrSlice["id"] = s[".name"]
        StrSlice["enable"] = s["enable"]
        table.insert(All, StrSlice)
    end)
    return All
end

function urlEncode(s)
    s = string.gsub(s, "([^%w%.%- ])", function(c) return string.format("%%%02X", string.byte(c)) end)
   return string.gsub(s, " ", "+")
end

function urlDecode(s)
   s = string.gsub(s, '%%(%x%x)', function(h) return string.char(tonumber(h, 16)) end)
   return s
end

function Diff(tableA, tableB)
    if type(tableA) ~= "table" or type(tableB) ~= "table" then
        return nil, nil
    end
    if table.getn(tableA) <= 0 and table.getn(tableB) <= 0 then
        return {}, {}
    end
    if table.getn(tableA) <= 0 and table.getn(tableB) > 0 then
        return {}, tableB
    end
    if table.getn(tableB) <= 0 and table.getn(tableA) > 0 then
        return tableA, {}
    end
    local temp = {}
    for _, v in pairs(tableA) do
        if temp[v] == nil then
            temp[v] = 1
        end
    end
    for _, v in pairs(tableB) do
        if temp[v] == nil then
            temp[v] = -1
        else
            temp[v] = 0
        end
    end
    local Add = {}
    local Del = {}
    for k, v in pairs(temp) do
        if v ~= 0 then
            if v == -1 then
                table.insert(Add, k)
            end
            if v == 1 then
                table.insert(Del, k)
            end
        end
    end
    return Add, Del
end