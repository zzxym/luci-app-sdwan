local http = luci.http

m = Map("sdwan", translate("SDWAN Status"))
m.description = translate("A simple, secure, decentralized VPN solution for intranet penetration, implemented in Rust using the Tokio framework. "
        .. "Project URL: <a href=\"https://github.com/zzxym/sdwan\" target=\"_blank\">github.com/zzxym/sdwan</a>&nbsp;&nbsp;"
        .. "<a href=\"http://sdwan.cn\" target=\"_blank\">Official Documentation</a>&nbsp;&nbsp;"
        .. "<a href=\"http://qm.qq.com/cgi-bin/qm/qr?_wv=1027&k=jhP2Z4UsEZ8wvfGPLrs0VwLKn_uz0Q_p&authKey=OGKSQLfg61YPCpVQuvx%2BxE7hUKBVBEVi9PljrDKbHlle6xqOXx8sOwPPTncMambK&noverify=0&group_code=949700262\" target=\"_blank\">QQ Group</a>&nbsp;&nbsp;")
        .. "<a href=\"https://github.com/zzxym/sdwan/releases\" target=\"_blank\"><img alt=\"\" src=\"https://img.shields.io/github/v/tag/zzxym/sdwan?include_prereleases&logo=github&label=tag&link=https%3A%2F%2Fgithub.com%2Fzzxym%2Fsdwan%2Freleases\" style=\"vertical-align:middle;\"></a>&nbsp;"
        .. "<a href=\"https://github.com/zzxym/sdwan/releases\" target=\"_blank\"><img alt=\"\" src=\"https://img.shields.io/github/v/release/zzxym/sdwan?logo=github&link=https%3A%2F%2Fgithub.com%2Fzzxym%2Fsdwan%2Freleases\" style=\"vertical-align:middle;\"></a>&nbsp;"
        .. "<a href=\"https://github.com/zzxym/luci-app-sdwan/releases\" target=\"_blank\"><img alt=\"\" src=\"https://img.shields.io/github/v/release/zzxym/luci-app-sdwan?logo=openwrt&label=luci&link=https%3A%2F%2Fgithub.com%2Fzzxym%2Fluci-app-sdwan%2Freleases\" style=\"vertical-align:middle;\"></a>"
m.pageaction = false

-- 状态卡片
m:section(SimpleSection).template = "sdwan/sdwan_status"

-- 连接信息卡片
m:section(SimpleSection).template = "sdwan/sdwan_cli"

return m
