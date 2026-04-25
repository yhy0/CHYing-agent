进入 docker ，启动 docker 容器

配置 .env 参考 .env.example

uv run main.py -t http://xxxxx


注意 agent-work/.mcp.json 中的
```

"visibility": "subagent:browser"

```

需要定制化适配，原理参考 https://mp.weixin.qq.com/s/7NHo3C8tDyO1vQsuBu5mog

这里的 二开后的 CC cli 就不开源了，想要类似的 mcp 可控性配置可以让 Claude 阅读泄露的源码后自行修改
