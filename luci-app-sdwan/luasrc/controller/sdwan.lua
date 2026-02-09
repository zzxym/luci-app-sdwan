
module("luci.controller.sdwan", package.seeall)

-- 安全执行命令并返回结果
local function safe_exec(cmd)
    local handle = io.popen(cmd)
    if not handle then return "" end
    local result = handle:read("*all") or ""
    handle:close()
    return result:gsub("[\r\n]+$", "")
end

-- 安全读取文件内容
local function safe_read_file(path)
    local file = io.open(path, "r")
    if not file then return nil end
    local content = file:read("*all")
    file:close()
    return content
end

-- 计算运行时长
local function calc_uptime(start_time_file)
    local content = safe_read_file(start_time_file)
    if not content or content == "" then return "" end
    
    local start_time = tonumber(content:match("%d+"))
    if not start_time then return "" end
    
    local now = os.time()
    local elapsed = now - start_time
    
    local days = math.floor(elapsed / 86400)
    local hours = math.floor((elapsed % 86400) / 3600)
    local mins = math.floor((elapsed % 3600) / 60)
    local secs = elapsed % 60
    
    local result = ""
    if days > 0 then result = days .. "天 " end
    result = result .. string.format("%02d小时%02d分%02d秒", hours, mins, secs)
    return result
end

function index()
	if not nixio.fs.access("/etc/config/sdwan") then
		return
	end
                  
        entry({"admin", "vpn", "sdwan"}, alias("admin", "vpn", "sdwan", "sdwan"),_("SDWAN"), 46).dependent = true
	entry({"admin", "vpn", "sdwan", "sdwan"}, cbi("sdwan"),_("SDWAN"), 47).leaf = true
	entry({"admin", "vpn",  "sdwan",  "sdwan_log"}, form("sdwan_log"),_("core log"), 48).leaf = true
	entry({"admin", "vpn", "sdwan", "get_log"}, call("get_log")).leaf = true
	entry({"admin", "vpn", "sdwan", "clear_log"}, call("clear_log")).leaf = true
	entry({"admin", "vpn",  "sdwan",  "sdwanweb_log"}, form("sdwanweb_log"),_("web log"), 49).leaf = true
	entry({"admin", "vpn", "sdwan", "get_wlog"}, call("get_wlog")).leaf = true
	entry({"admin", "vpn", "sdwan", "clear_wlog"}, call("clear_wlog")).leaf = true
	entry({"admin", "vpn", "sdwan", "status"}, call("act_status")).leaf = true
	entry({"admin", "vpn", "sdwan", "conninfo"}, call("act_conninfo")).leaf = true
end

function act_status()
	local e = {}
	local sys  = require "luci.sys"
	local uci  = require "luci.model.uci".cursor()
	local port = tonumber(uci:get_first("sdwan", "sdwan", "web_html_port"))
	e.crunning = luci.sys.call("pgrep sdwan-core >/dev/null") == 0
	e.wrunning = luci.sys.call("pgrep sdwan-web >/dev/null") == 0
	e.port = (port or 0)
	
	-- 使用 Lua 原生计算运行时长
	e.etsta = calc_uptime("/tmp/sdwan_time")
	e.etwebsta = calc_uptime("/tmp/sdwanweb_time")
	
	-- 获取 CPU 和内存使用率（使用原始命令）
	local command2 = io.popen('test ! -z "`pidof sdwan-core`" && (top -b -n1 | grep -E "$(pidof sdwan-core)" 2>/dev/null | grep -v grep | awk \'{for (i=1;i<=NF;i++) {if ($i ~ /sdwan-core/) break; else cpu=i}} END {print $cpu}\')')
	e.etcpu = command2:read("*all")
	command2:close()
	
	local command3 = io.popen("test ! -z `pidof sdwan-core` && (cat /proc/$(pidof sdwan-core | awk '{print $NF}')/status | grep -w VmRSS | awk '{printf \"%.2f MB\", $2/1024}')")
	e.etram = command3:read("*all")
	command3:close()
	
	local command4 = io.popen('test ! -z "`pidof sdwan-web`" && (top -b -n1 | grep -E "$(pidof sdwan-web)" 2>/dev/null | grep -v grep | awk \'{for (i=1;i<=NF;i++) {if ($i ~ /sdwan-web/) break; else cpu=i}} END {print $cpu}\')')
	e.etwebcpu = command4:read("*all")
	command4:close()
	
	local command5 = io.popen("test ! -z `pidof sdwan-web` && (cat /proc/$(pidof sdwan-web | awk '{print $NF}')/status | grep -w VmRSS | awk '{printf \"%.2f MB\", $2/1024}')")
	e.etwebram = command5:read("*all")
	command5:close()
	
	-- 获取版本信息
	local cached_newtag = safe_read_file("/tmp/sdwannew.tag")
	if cached_newtag and cached_newtag ~= "" then
		e.etnewtag = cached_newtag:gsub("[\r\n]+", "")
	else
		e.etnewtag = safe_exec("curl -L -k -s --connect-timeout 3 --user-agent 'Mozilla/5.0' https://api.github.com/repos/SDWAN/SDWAN/releases/latest | grep tag_name | sed 's/[^0-9.]*//g'")
		if e.etnewtag ~= "" then
			local f = io.open("/tmp/sdwannew.tag", "w")
			if f then f:write(e.etnewtag); f:close() end
		end
	end
	
	local cached_tag = safe_read_file("/tmp/sdwan.tag")
	if cached_tag and cached_tag ~= "" then
		e.ettag = cached_tag:gsub("[\r\n]+", "")
	else
		local sdwanbin = uci:get_first("sdwan", "sdwan", "sdwanbin") or "/usr/bin/sdwan-core"
		e.ettag = safe_exec(sdwanbin .. " -V | sed 's/^[^0-9]*//'")
		if e.ettag == "" then e.ettag = "?" end
		local f = io.open("/tmp/sdwan.tag", "w")
		if f then f:write(e.ettag); f:close() end
	end

	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end


function get_log()
    local log = ""
    local files = {"/tmp/sdwan.log"}
    for i, file in ipairs(files) do
        if luci.sys.call("[ -f '" .. file .. "' ]") == 0 then
            log = log .. luci.sys.exec("sed 's/\\x1b\\[[0-9;]*m//g' " .. file)
        end
    end
    luci.http.write(log)
end

function clear_log()
	luci.sys.call("echo '' >/tmp/sdwan.log")
end

function get_wlog()
    local log = ""
    local files = {"/tmp/sdwanweb.log"}
    for i, file in ipairs(files) do
        if luci.sys.call("[ -f '" .. file .. "' ]") == 0 then
            log = log .. luci.sys.exec("sed 's/\\x1b\\[[0-9;]*m//g' " .. file)
        end
    end
    luci.http.write(log)
end

function clear_wlog()
	luci.sys.call("echo '' >/tmp/sdwanweb.log")
end

function act_conninfo()
	local e = {}
	local uci = require "luci.model.uci".cursor()
	local sdwanbin = uci:get_first("sdwan", "sdwan", "sdwanbin") or "/usr/bin/sdwan-core"
	local clibin = sdwanbin:gsub("sdwan%-core$", "sdwan-cli")
	
	local process_status = luci.sys.exec("pgrep sdwan-core")
	
	if process_status ~= "" then
		-- 获取各类CLI信息
		local function get_cli_output(cmd)
			local handle = io.popen(clibin .. " " .. cmd .. " 2>&1")
			if handle then
				local result = handle:read("*all")
				handle:close()
				return result or ""
			end
			return ""
		end
		
		e.node = get_cli_output("node")
		e.peer = get_cli_output("peer")
		e.connector = get_cli_output("connector")
		e.stun = get_cli_output("stun")
		e.route = get_cli_output("route")
		e.peer_center = get_cli_output("peer-center")
		e.vpn_portal = get_cli_output("vpn-portal")
		e.proxy = get_cli_output("proxy")
		e.acl = get_cli_output("acl stats")
		e.mapped_listener = get_cli_output("mapped-listener")
		e.stats = get_cli_output("stats")
		
		-- 获取启动参数
		local cmdhandle = io.popen("cat /proc/$(pidof sdwan-core)/cmdline 2>/dev/null | tr '\\0' ' '")
		if cmdhandle then
			e.cmdline = cmdhandle:read("*all") or ""
			cmdhandle:close()
		else
			e.cmdline = ""
		end
	else
		local errMsg = "错误：程序未运行！请启动程序后刷新"
		e.node = errMsg
		e.peer = errMsg
		e.connector = errMsg
		e.stun = errMsg
		e.route = errMsg
		e.peer_center = errMsg
		e.vpn_portal = errMsg
		e.proxy = errMsg
		e.acl = errMsg
		e.mapped_listener = errMsg
		e.stats = errMsg
		e.cmdline = errMsg
	end
	
	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end
