local http = luci.http

m = Map("sdwan", translate("SDWAN Status"))
m.pageaction = false

-- 状态卡片
m:section(SimpleSection).template = "sdwan/sdwan_status"

-- 连接信息卡片
m:section(SimpleSection).template = "sdwan/sdwan_cli"

return m
