#!/bin/sh
# sdwan Firewall Management
# Manages firewall rules and network interfaces for sdwan

# 引入工具函数
. /usr/share/sdwan/utils.sh 2>/dev/null || true

# 添加单条防火墙规则
# 参数: $1=规则名称 $2=协议 $3=端口 $4=描述
add_firewall_rule() {
	local rule_name="$1"
	local proto="$2"
	local port="$3"
	local desc="$4"
	
	[ -z "$port" ] && return 1
	
	log_message "INFO" "sdwan" "添加防火墙规则 ${rule_name} 放行端口 ${port}" "/tmp/sdwan.log"
	
	uci -q delete "firewall.${rule_name}"
	uci set "firewall.${rule_name}=rule"
	uci set "firewall.${rule_name}.name=${rule_name}"
	uci set "firewall.${rule_name}.target=ACCEPT"
	uci set "firewall.${rule_name}.src=wan"
	uci set "firewall.${rule_name}.proto=${proto}"
	uci set "firewall.${rule_name}.dest_port=${port}"
	uci set "firewall.${rule_name}.enabled=1"
}

# 设置所有 sdwan 防火墙规则
# 需要设置的变量: tcp_port, udp_port, ws_port, wss_port, wg_port, quic_port, socks_port
set_firewall_rules() {
	[ -n "$tcp_port" ] && add_firewall_rule "sdwan_tcp_udp" "tcp udp" "$tcp_port" "sdwan TCP/UDP"
	[ -n "$udp_port" ] && add_firewall_rule "sdwan_udp" "udp" "$udp_port" "sdwan UDP"
	[ -n "$ws_port" ] && add_firewall_rule "sdwan_ws" "tcp" "$ws_port" "sdwan WS"
	[ -n "$wss_port" ] && add_firewall_rule "sdwan_wss" "tcp" "$wss_port" "sdwan WSS"
	[ -n "$wg_port" ] && add_firewall_rule "sdwan_wg" "udp" "$wg_port" "sdwan WG"
	[ -n "$quic_port" ] && add_firewall_rule "sdwan_quic" "tcp udp" "$quic_port" "sdwan QUIC"
	[ -n "$socks_port" ] && add_firewall_rule "sdwan_socks5" "tcp" "$socks_port" "sdwan SOCKS5"
}

# 设置网络接口
# 参数: $1=接口名称 $2=IP地址(可选)
setup_network_interface() {
	local tunname="${1:-tun0}"
	local ipaddr="$2"
	
	uci -q delete network.sdwan >/dev/null 2>&1
	
	if [ -z "$(uci -q get network.sdwan)" ]; then
		uci set network.sdwan='interface'
		if [ -z "$ipaddr" ]; then
			uci set network.sdwan.proto='none'
		else
			uci set network.sdwan.proto='static'
			uci set network.sdwan.ipaddr="$ipaddr"
			uci set network.sdwan.netmask='255.0.0.0'
		fi
		log_message "INFO" "sdwan" "添加网络接口 sdwan 绑定虚拟接口 ${tunname}" "/tmp/sdwan.log"
		uci set network.sdwan.device="$tunname"
		uci set network.sdwan.ifname="$tunname"
	fi
}

# 设置防火墙区域
setup_firewall_zone() {
	if [ -z "$(uci -q get firewall.sdwanzone)" ]; then
		log_message "INFO" "sdwan" "添加防火墙规则，放行网络接口 sdwan 允许出入转发，开启IP动态伪装 MSS钳制" "/tmp/sdwan.log"
		uci set firewall.sdwanzone='zone'
		uci set firewall.sdwanzone.input='ACCEPT'
		uci set firewall.sdwanzone.output='ACCEPT'
		uci set firewall.sdwanzone.forward='ACCEPT'
		uci set firewall.sdwanzone.masq='1'
		uci set firewall.sdwanzone.mtu_fix='1'
		uci set firewall.sdwanzone.name='sdwan'
		uci set firewall.sdwanzone.network='sdwan'
	fi
}

# 设置转发规则
# 参数: $1=et_forward 配置值
setup_forwarding_rules() {
	local et_forward="$1"
	
	if [ "${et_forward#*etfwlan}" != "$et_forward" ]; then
		log_message "INFO" "sdwan" "允许从虚拟网络 sdwan 到局域网 lan 的流量" "/tmp/sdwan.log"
		uci set firewall.sdwanfwlan=forwarding
		uci set firewall.sdwanfwlan.dest='lan'
		uci set firewall.sdwanfwlan.src='sdwan'
	else
		uci -q delete firewall.sdwanfwlan
	fi
	
	if [ "${et_forward#*etfwwan}" != "$et_forward" ]; then
		log_message "INFO" "sdwan" "允许从虚拟网络 sdwan 到广域网 wan 的流量" "/tmp/sdwan.log"
		uci set firewall.sdwanfwwan=forwarding
		uci set firewall.sdwanfwwan.dest='wan'
		uci set firewall.sdwanfwwan.src='sdwan'
	else
		uci -q delete firewall.sdwanfwwan
	fi
	
	if [ "${et_forward#*lanfwet}" != "$et_forward" ]; then
		log_message "INFO" "sdwan" "允许从局域网 lan 到虚拟网络 sdwan 的流量" "/tmp/sdwan.log"
		uci set firewall.lanfwsdwan=forwarding
		uci set firewall.lanfwsdwan.dest='sdwan'
		uci set firewall.lanfwsdwan.src='lan'
	else
		uci -q delete firewall.lanfwsdwan
	fi
	
	if [ "${et_forward#*wanfwet}" != "$et_forward" ]; then
		log_message "INFO" "sdwan" "允许从广域网 wan 到虚拟网络 sdwan 的流量" "/tmp/sdwan.log"
		uci set firewall.wanfwsdwan=forwarding
		uci set firewall.wanfwsdwan.dest='sdwan'
		uci set firewall.wanfwsdwan.src='wan'
	else
		uci -q delete firewall.wanfwsdwan
	fi
}

# 清理所有 sdwan 防火墙规则
clean_firewall_rules() {
	uci -q delete network.sdwan >/dev/null 2>&1
	uci -q delete firewall.sdwanzone >/dev/null 2>&1
	uci -q delete firewall.sdwanfwlan >/dev/null 2>&1
	uci -q delete firewall.sdwanfwwan >/dev/null 2>&1
	uci -q delete firewall.lanfwsdwan >/dev/null 2>&1
	uci -q delete firewall.wanfwsdwan >/dev/null 2>&1
	uci -q delete firewall.sdwan_tcp >/dev/null 2>&1
	uci -q delete firewall.sdwan_udp >/dev/null 2>&1
	uci -q delete firewall.sdwan_tcp_udp >/dev/null 2>&1
	uci -q delete firewall.sdwan_wss >/dev/null 2>&1
	uci -q delete firewall.sdwan_ws >/dev/null 2>&1
	uci -q delete firewall.sdwan_wg >/dev/null 2>&1
	uci -q delete firewall.sdwan_quic >/dev/null 2>&1
	uci -q delete firewall.sdwan_wireguard >/dev/null 2>&1
	uci -q delete firewall.sdwan_socks5 >/dev/null 2>&1
	uci -q delete firewall.sdwan_webserver >/dev/null 2>&1
	uci -q delete firewall.sdwan_webapi >/dev/null 2>&1
	uci -q delete firewall.sdwan_webhtml >/dev/null 2>&1
}

# 设置 Web 控制台防火墙规则
# 参数: $1=web_port $2=api_port $3=html_port $4=fw_web $5=fw_api
setup_web_firewall() {
	local web_port="$1"
	local api_port="$2"
	local html_port="$3"
	local fw_web="$4"
	local fw_api="$5"
	
	if [ -n "$web_port" ] && [ "$fw_web" = "1" ]; then
		log_message "INFO" "sdwan" "添加防火墙规则 sdwan_web 放行服务端口 ${web_port}" "/tmp/sdwanweb.log"
		uci -q delete firewall.sdwan_webserver
		uci set firewall.sdwan_webserver=rule
		uci set firewall.sdwan_webserver.name="sdwan_webserver"
		uci set firewall.sdwan_webserver.target="ACCEPT"
		uci set firewall.sdwan_webserver.src="wan"
		uci set firewall.sdwan_webserver.proto="tcp udp"
		uci set firewall.sdwan_webserver.dest_port="$web_port"
		uci set firewall.sdwan_webserver.enabled="1"
	fi
	
	if [ -n "$api_port" ] && [ "$fw_api" = "1" ]; then
		log_message "INFO" "sdwan" "添加防火墙规则 sdwan_web 放行API端口 ${api_port}" "/tmp/sdwanweb.log"
		uci -q delete firewall.sdwan_webapi
		uci set firewall.sdwan_webapi=rule
		uci set firewall.sdwan_webapi.name="sdwan_webapi"
		uci set firewall.sdwan_webapi.target="ACCEPT"
		uci set firewall.sdwan_webapi.src="wan"
		uci set firewall.sdwan_webapi.proto="tcp"
		uci set firewall.sdwan_webapi.dest_port="$api_port"
		uci set firewall.sdwan_webapi.enabled="1"
	fi
	
	if [ -n "$html_port" ] && [ "$fw_api" = "1" ] && [ "$html_port" != "$api_port" ]; then
		log_message "INFO" "sdwan" "添加防火墙规则 sdwan_web 放行html端口 ${html_port}" "/tmp/sdwanweb.log"
		uci -q delete firewall.sdwan_webhtml
		uci set firewall.sdwan_webhtml=rule
		uci set firewall.sdwan_webhtml.name="sdwan_webhtml"
		uci set firewall.sdwan_webhtml.target="ACCEPT"
		uci set firewall.sdwan_webhtml.src="wan"
		uci set firewall.sdwan_webhtml.proto="tcp"
		uci set firewall.sdwan_webhtml.dest_port="$html_port"
		uci set firewall.sdwan_webhtml.enabled="1"
	fi
}

# 应用防火墙和网络配置更改
apply_network_changes() {
	[ -n "$(uci changes network)" ] && uci commit network && /etc/init.d/network reload >/dev/null 2>&1
	[ -n "$(uci changes firewall)" ] && uci commit firewall && /etc/init.d/firewall reload >/dev/null 2>&1
}
