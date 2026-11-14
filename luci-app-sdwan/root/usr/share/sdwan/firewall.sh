#!/bin/sh
# SDWAN Firewall Management
# 虚拟网卡直接加入 lan 区域，与局域网天然互通，
# 不再创建独立 zone，也不需要任何跨区域转发规则。

. /usr/share/sdwan/utils.sh 2>/dev/null || true

if ! command -v log_message >/dev/null 2>&1; then
	log_message() { :; }
fi

SDWAN_NETWORK="SDWAN"

# 查找 lan 区域的 uci section（兼容 @zone[0] 与具名 section）
sdwan_lan_zone() {
	uci -q show firewall | sed -n "s/^firewall\.\([^.]*\)\.name='lan'$/\1/p" | head -n 1
}

# 从 lan 区域移除虚拟网卡
sdwan_detach_lan_zone() {
	local zone
	zone="$(sdwan_lan_zone)"
	[ -n "$zone" ] && uci -q del_list "firewall.${zone}.network=${SDWAN_NETWORK}"
	return 0
}

# 清理旧版本创建的独立 zone 与跨区域转发规则
sdwan_remove_legacy_rules() {
	uci -q delete firewall.sdwanzone
	uci -q delete firewall.sdwanfwlan
	uci -q delete firewall.sdwanfwwan
	uci -q delete firewall.lanfwsdwan
	uci -q delete firewall.wanfwsdwan
}

# 放行 WAN 侧主动连入的监听端口（外部节点接入用，与局域网互通无关）
sdwan_add_wan_rule() {
	local name="$1" proto="$2" port="$3"
	[ -n "$port" ] || return 0
	uci -q delete "firewall.${name}" >/dev/null 2>&1
	uci set "firewall.${name}=rule"
	uci set "firewall.${name}.name=${name}"
	uci set "firewall.${name}.target=ACCEPT"
	uci set "firewall.${name}.src=wan"
	uci set "firewall.${name}.proto=${proto}"
	uci set "firewall.${name}.dest_port=${port}"
	uci set "firewall.${name}.enabled=1"
}

sdwan_allow_wan_ports() {
	sdwan_add_wan_rule sdwan_tcp_udp "tcp udp" "$tcp_port"
	sdwan_add_wan_rule sdwan_ws "tcp" "$ws_port"
	sdwan_add_wan_rule sdwan_wss "tcp" "$wss_port"
	sdwan_add_wan_rule sdwan_wg "udp" "$wg_port"
	sdwan_add_wan_rule sdwan_quic "tcp udp" "$quic_port"
	sdwan_add_wan_rule sdwan_socks5 "tcp" "$socks_port"
}

# 创建虚拟网卡接口并加入 lan 区域
# 参数: $1=tunname $2=ipaddr(可空) $3=netmask
setup_sdwan_lan_zone() {
	local tunname="${1:-tun0}" ipaddr="$2" netmask="${3:-255.0.0.0}" zone

	uci -q delete "network.${SDWAN_NETWORK}" >/dev/null 2>&1
	uci set "network.${SDWAN_NETWORK}=interface"
	if [ -z "$ipaddr" ]; then
		uci set "network.${SDWAN_NETWORK}.proto=none"
	else
		uci set "network.${SDWAN_NETWORK}.proto=static"
		uci set "network.${SDWAN_NETWORK}.ipaddr=${ipaddr}"
		uci set "network.${SDWAN_NETWORK}.netmask=${netmask}"
	fi
	uci set "network.${SDWAN_NETWORK}.device=${tunname}"
	uci set "network.${SDWAN_NETWORK}.ifname=${tunname}"

	sdwan_remove_legacy_rules
	zone="$(sdwan_lan_zone)"
	if [ -n "$zone" ]; then
		uci -q del_list "firewall.${zone}.network=${SDWAN_NETWORK}"
		uci add_list "firewall.${zone}.network=${SDWAN_NETWORK}"
		log_message "INFO" "sdwan" "虚拟网卡 ${tunname} 已加入 lan 区域，与局域网直接互通" "/tmp/sdwan.log"
	else
		log_message "WARN" "sdwan" "未找到 lan 区域，请手动将 ${SDWAN_NETWORK} 加入防火墙区域" "/tmp/sdwan.log"
	fi
}

# 停止服务时清理全部改动
cleanup_sdwan_firewall() {
	local r
	sdwan_detach_lan_zone
	sdwan_remove_legacy_rules
	uci -q delete "network.${SDWAN_NETWORK}" >/dev/null 2>&1
	for r in sdwan_tcp_udp sdwan_udp sdwan_ws sdwan_wss sdwan_wg sdwan_quic \
	         sdwan_wireguard sdwan_socks5 sdwan_webserver sdwan_webapi sdwan_webhtml; do
		uci -q delete "firewall.${r}" >/dev/null 2>&1
	done
}

# 应用防火墙和网络配置更改（延迟后台执行）
apply_network_changes() {
	if [ -n "$(uci changes network)" ] || [ -n "$(uci changes firewall)" ]; then
		(
			sleep 5
			LOCK_FILE="/var/lock/sdwan_reload.lock"
			if [ ! -f "$LOCK_FILE" ]; then
				touch "$LOCK_FILE"
				[ -n "$(uci changes network)" ] && uci commit network && /etc/init.d/network reload >/dev/null 2>&1
				[ -n "$(uci changes firewall)" ] && uci commit firewall && /etc/init.d/firewall reload >/dev/null 2>&1
				rm -f "$LOCK_FILE"
			fi
		) &
	fi
}
