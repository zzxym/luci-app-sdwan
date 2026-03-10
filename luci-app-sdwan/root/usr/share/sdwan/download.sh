#!/bin/sh
# sdwan Download Management
# Handles binary downloads from GitHub with proxy support

# 引入工具函数
. /usr/share/sdwan/utils.sh 2>/dev/null || true

# 默认 GitHub 加速代理列表
DEFAULT_PROXYS="
https://ghproxy.net/
https://gh-proxy.com/
https://cdn.gh-proxy.com/
https://ghfast.top/
"

# 获取代理列表
# 优先从 UCI 配置读取，否则使用默认值
get_proxy_list() {
	local proxys=$(uci -q get sdwan.@sdwan[0].github_proxys)
	[ -z "$proxys" ] && proxys="$DEFAULT_PROXYS"
	echo "$proxys"
}

# 获取最新版本号
get_latest_version() {
	local user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
	local tag=""
	local curltest=$(which curl)
	
	if [ -z "$curltest" ] || [ ! -s "$(which curl)" ]; then
		tag=$(wget --no-check-certificate -T 5 -t 3 --user-agent "$user_agent" --max-redirect=0 --output-document=- \
			https://api.github.com/repos/sdwan/sdwan/releases/latest 2>&1 | grep 'tag_name' | cut -d\" -f4)
		[ -z "$tag" ] && tag=$(wget --no-check-certificate -T 5 -t 3 --user-agent "$user_agent" --quiet --output-document=- \
			https://api.github.com/repos/sdwan/sdwan/releases/latest 2>&1 | grep 'tag_name' | cut -d\" -f4)
	else
		tag=$(curl -k --connect-timeout 3 --user-agent "$user_agent" \
			https://api.github.com/repos/sdwan/sdwan/releases/latest 2>&1 | grep 'tag_name' | cut -d\" -f4)
		[ -z "$tag" ] && tag=$(curl -Lk --connect-timeout 3 --user-agent "$user_agent" -s \
			https://api.github.com/repos/sdwan/sdwan/releases/latest 2>&1 | grep 'tag_name' | cut -d\" -f4)
	fi
	
	# 如果获取失败，从 UCI 配置或使用默认版本
	if [ -z "$tag" ]; then
		tag=$(uci -q get sdwan.@sdwan[0].fallback_version)
		[ -z "$tag" ] && tag="v2.5.0"
	fi
	
	echo "$tag"
}

# 下载二进制文件
# 参数: $1=版本号 $2=CPU架构 $3=目标路径
download_binary() {
	local tag="$1"
	local cpucore="$2"
	local path="$3"
	local proxys=$(get_proxy_list)
	local download_url="https://github.com/sdwan/sdwan/releases/download/${tag}/sdwan-linux-${cpucore}-${tag}.zip"
	
	mkdir -p "$path"
	
	for proxy in $proxys; do
		log_message "INFO" "sdwan" "尝试使用代理 ${proxy} 下载" "/tmp/sdwan.log"
		
		if curl -L -k -o /tmp/sdwan.zip --connect-timeout 10 --retry 3 "${proxy}${download_url}" || \
		   wget --no-check-certificate --timeout=10 --tries=3 -O /tmp/sdwan.zip "${proxy}${download_url}"; then
			
			unzip -j -q -o /tmp/sdwan.zip -d /tmp
			chmod +x /tmp/sdwan-core /tmp/sdwan-cli /tmp/sdwan-web /tmp/sdwan-web-embed 2>/dev/null || true
			rm -rf /tmp/sdwan.zip
			
			log_message "INFO" "sdwan" "下载成功" "/tmp/sdwan.log"
			return 0
		else
			log_message "WARN" "sdwan" "${proxy}${download_url} 下载失败" "/tmp/sdwan.log"
		fi
	done
	
	log_message "ERROR" "sdwan" "所有代理下载均失败，请手动下载上传程序" "/tmp/sdwan.log"
	return 1
}

# 检查并下载程序
# 参数: $1=程序路径 $2=目标路径 $3=CPU架构
check_and_download() {
	local sdwanbin="$1"
	local path="$2"
	local cpucore="$3"
	
	# 检查程序是否存在且完整
	if [ ! -f "$sdwanbin" ] || [ "$($sdwanbin -h 2>&1 | wc -l)" -lt 3 ]; then
		log_message "INFO" "sdwan" "$sdwanbin 不存在或程序不完整，开始在线下载..." "/tmp/sdwan.log"
		
		local tag=$(get_latest_version)
		log_message "INFO" "sdwan" "开始在线下载${tag}版本" "/tmp/sdwan.log"
		
		if download_binary "$tag" "$cpucore" "$path"; then
			# 移动下载的文件到目标位置
			if [ "$(uci -q get sdwan.@sdwan[0].enabled)" = "1" ]; then
				mv -f /tmp/sdwan-core "${path}/" 2>/dev/null
				mv -f /tmp/sdwan-cli "${path}/" 2>/dev/null
				chmod +x "$sdwanbin" 2>/dev/null
			fi
			
			if [ "$(uci -q get sdwan.@sdwan[0].web_enabled)" = "1" ]; then
				local webbin=$(uci -q get sdwan.@sdwan[0].webbin)
				[ -z "$webbin" ] && webbin="/usr/bin/sdwan-web"
				mv -f /tmp/sdwan-web-embed "$webbin" 2>/dev/null || true
				chmod +x "$webbin" 2>/dev/null
			fi
			
			return 0
		fi
		
		return 1
	fi
	
	return 0
}

# 处理上传的程序
# 参数: $1=目标路径 $2=程序路径
handle_uploaded_binary() {
	local path="$1"
	local sdwanbin="$2"
	local size=$(get_available_space "$path")
	
	if [ -f /tmp/sdwan-core ] || [ -f /tmp/sdwan-cli ]; then
		if [ "${path:0:4}" != "/tmp" ]; then
			chmod +x /tmp/sdwan-core 2>/dev/null
			chmod +x /tmp/sdwan-cli 2>/dev/null
			mkdir -p "$path"
			
			log_message "INFO" "sdwan" "找到上传的程序/tmp/sdwan-core，替换为$sdwanbin" "/tmp/sdwan.log"
			
			local upsize=$(du -k /tmp/sdwan-core 2>/dev/null | cut -f1)
			local result=$((size - upsize))
			
			if [ "$(/tmp/sdwan-core -h 2>&1 | wc -l)" -gt 3 ] && [ "$result" -gt 1000 ]; then
				mv -f /tmp/sdwan-core "$sdwanbin" 2>/dev/null
				mv -f /tmp/sdwan-cli "${path}/sdwan-cli" 2>/dev/null
				return 0
			else
				log_message "WARN" "sdwan" "无法替换，上传的程序不完整或自定义路径的可用空间不足，当前空间剩余${size}kb" "/tmp/sdwan.log"
				return 1
			fi
		fi
	fi
	
	return 1
}
