f = SimpleForm("sdwan")
f.reset = false
f.submit = false
f:append(Template("sdwan/sdwan_log"))
return f
