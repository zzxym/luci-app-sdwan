f = SimpleForm("sdwan")
f.reset = false
f.submit = false
f:append(Template("sdwan/sdwanweb_log"))
return f
