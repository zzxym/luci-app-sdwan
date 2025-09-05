
module("luci.controller.sdwan", package.seeall)

function index()
	if not nixio.fs.access("/etc/config/sdwan") then
		return
	end
                  
        entry({"admin", "vpn", "sdwan"}, alias("admin", "vpn", "sdwan", "sdwan"),_("sdwan"), 46).dependent = true
	entry({"admin", "vpn", "sdwan", "sdwan"}, cbi("sdwan"),_("sdwan"), 47).leaf = true
	entry({"admin", "vpn",  "sdwan",  "sdwan_log"}, form("sdwan_log"),_("core log"), 48).leaf = true
	entry({"admin", "vpn", "sdwan", "get_log"}, call("get_log")).leaf = true
	entry({"admin", "vpn", "sdwan", "clear_log"}, call("clear_log")).leaf = true
	entry({"admin", "vpn",  "sdwan",  "sdwanweb_log"}, form("sdwanweb_log"),_("web log"), 49).leaf = true
	entry({"admin", "vpn", "sdwan", "get_wlog"}, call("get_wlog")).leaf = true
	entry({"admin", "vpn", "sdwan", "clear_wlog"}, call("clear_wlog")).leaf = true
	entry({"admin", "vpn", "sdwan", "status"}, call("act_status")).leaf = true
end

function act_status()
	local e = {}
	local sys  = require "luci.sys"
	local uci  = require "luci.model.uci".cursor()
	local port = tonumber(uci:get_first("sdwan", "sdwanweb", "html_port"))
	e.crunning = luci.sys.call("pgrep sdwan-core >/dev/null") == 0
	e.wrunning = luci.sys.call("pgrep sdwan-web >/dev/null") == 0
	e.port = (port or 0)
	
	local tagfile = io.open("/tmp/sdwan_time", "r")
        if tagfile then
		local tagcontent = tagfile:read("*all")
		tagfile:close()
		if tagcontent and tagcontent ~= "" then
        		os.execute("start_time=$(cat /tmp/sdwan_time) && time=$(($(date +%s)-start_time)) && day=$((time/86400)) && [ $day -eq 0 ] && day='' || day=${day}天 && time=$(date -u -d @${time} +'%H小时%M分%S秒') && echo $day $time > /tmp/command_sdwan 2>&1")
        		local command_output_file = io.open("/tmp/command_sdwan", "r")
        		if command_output_file then
            			e.etsta = command_output_file:read("*all")
            			command_output_file:close()
        		end
		end
	end
	
        local command2 = io.popen('test ! -z "`pidof sdwan-core`" && (top -b -n1 | grep -E "$(pidof sdwan-core)" 2>/dev/null | grep -v grep | awk \'{for (i=1;i<=NF;i++) {if ($i ~ /sdwan-core/) break; else cpu=i}} END {print $cpu}\')')
	e.etcpu = command2:read("*all")
	command2:close()
	
        local command3 = io.popen("test ! -z `pidof sdwan-core` && (cat /proc/$(pidof sdwan-core | awk '{print $NF}')/status | grep -w VmRSS | awk '{printf \"%.2f MB\", $2/1024}')")
	e.etram = command3:read("*all")
	command3:close()

	local wtagfile = io.open("/tmp/sdwanweb_time", "r")
        if wtagfile then
		local wtagcontent = wtagfile:read("*all")
		wtagfile:close()
		if wtagcontent and wtagcontent ~= "" then
        		os.execute("start_time=$(cat /tmp/sdwanweb_time) && time=$(($(date +%s)-start_time)) && day=$((time/86400)) && [ $day -eq 0 ] && day='' || day=${day}天 && time=$(date -u -d @${time} +'%H小时%M分%S秒') && echo $day $time > /tmp/command_sdwanweb 2>&1")
        		local wcommand_output_file = io.open("/tmp/command_sdwanweb", "r")
        		if wcommand_output_file then
            			e.etwebsta = wcommand_output_file:read("*all")
            			wcommand_output_file:close()
        		end
		end
	end

	local command4 = io.popen('test ! -z "`pidof sdwan-web`" && (top -b -n1 | grep -E "$(pidof sdwan-web)" 2>/dev/null | grep -v grep | awk \'{for (i=1;i<=NF;i++) {if ($i ~ /sdwan-web/) break; else cpu=i}} END {print $cpu}\')')
	e.etwebcpu = command4:read("*all")
	command4:close()
	
        local command5 = io.popen("test ! -z `pidof sdwan-web` && (cat /proc/$(pidof sdwan-web | awk '{print $NF}')/status | grep -w VmRSS | awk '{printf \"%.2f MB\", $2/1024}')")
	e.etwebram = command5:read("*all")
	command5:close()
	
        local command8 = io.popen("([ -s /tmp/sdwannew.tag ] && cat /tmp/sdwannew.tag ) || ( curl -L -k -s --connect-timeout 3 --user-agent 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36' https://api.github.com/repos/sdwan/sdwan/releases/latest | grep tag_name | sed 's/[^0-9.]*//g' >/tmp/sdwannew.tag && cat /tmp/sdwannew.tag )")
	e.etnewtag = command8:read("*all")
	command8:close()
	
        local command9 = io.popen("([ -s /tmp/sdwan.tag ] && cat /tmp/sdwan.tag ) || ( echo `$(uci -q get sdwan.@sdwan[0].sdwanbin) -V | sed 's/^[^0-9]*//'` > /tmp/sdwan.tag && cat /tmp/sdwan.tag && [ ! -s /tmp/sdwan.tag ] && echo '？' >> /tmp/sdwan.tag && cat /tmp/sdwan.tag )")
	e.ettag = command9:read("*all")
	command9:close()

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
