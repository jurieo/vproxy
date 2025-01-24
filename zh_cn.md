
# vproxy

一个高性能的 `HTTP`/`HTTPS`/`SOCKS5` 代理服务器

### 本项目仅为备份 防止上次github封号导致项目404 不存在篡改所有者版权和任何源码

## 特性

- IPv4/IPv6 优先级
- 可配置并发限制
- 服务绑定 `CIDR` 地址
- 指定 `CIDR` 子网范围
- 基础认证
- 代理扩展

### 安装方式

- wget

```bash
wget -O /tmp/install_vproxy.sh https://raw.githubusercontent.com/wx-11/vproxy/main/.github/install.sh && echo y | bash /tmp/install_vproxy.sh
```

- curl

```bash
curl -s -o /tmp/install_vproxy.sh https://raw.githubusercontent.com/wx-11/vproxy/main/.github/install.sh && echo y | bash /tmp/install_vproxy.sh
```

- Docker

```bash
docker run --rm -it ghcr.io/wx-11/vproxy:latest run http
```

- cargo

```bash
cargo install vproxy
```

## 使用手册

```shell
$ vproxy -h
一个高性能的 HTTP/HTTPS/SOCKS5 代理服务器

用法: vproxy
      vproxy <命令>

命令:
  run      运行服务器
  start    启动服务器守护进程
  restart  重启服务器守护进程
  stop     停止服务器守护进程
  ps       显示服务器守护进程状态
  log      显示服务器守护进程日志
  update   更新应用程序
  help     打印此帮助信息或指定子命令的帮助

选项:
  -h, --help     打印帮助信息
  -V, --version  打印版本信息

$ vproxy run -h
运行服务器

用法: vproxy run [选项] <命令>

命令:
  http    Http 服务器
  https   Https 服务器
  socks5  Socks5 服务器
  help    打印此帮助信息或指定子命令的帮助

选项:
      --log <LOG>
          日志级别，如 trace、debug、info、warn、error [环境变量: VPROXY_LOG=] [默认: info]
  -b, --bind <BIND>
          绑定地址 [默认: 0.0.0.0:1080]
  -T, --connect-timeout <CONNECT_TIMEOUT>
          连接超时时间(秒) [默认: 10]
  -c, --concurrent <CONCURRENT>
          并发连接数 [默认: 1024]
  -i, --cidr <CIDR>
          IP-CIDR，例如 2001:db8::/32
  -r, --cidr-range <CIDR_RANGE>
          IP-CIDR-Range，例如 64
  -f, --fallback <FALLBACK>
          回退地址 
  -h, --help
          打印帮助信息
```
fallback 作用参考 https://github.com/0x676e67/vproxy/issues/41#issuecomment-2111324521

### 注意事项

如果您使用[完全的root权限运行程序](https://github.com/0x676e67/vproxy/issues/118#issuecomment-2600935945)，它会自动为您配置 `sysctl net.ipv6.ip_nonlocal_bind=1` 和 `ip route add local 2001:470:e953::/48 dev lo`。如果权限不够，您需要手动配置这些选项。

如果未配置子网，将使用本地默认网络代理请求。当本地机器设置优先 `IPv4`/`IPv6` 且优先级为 `IPv4` 时，它将始终使用 `IPv4` 发出请求（如果有的话）。

```shell
# 启用绑定非本地 IPv6 地址
sudo sysctl net.ipv6.ip_nonlocal_bind=1

# 替换为您的 IPv6 子网
sudo ip route add local 2001:470:e953::/48 dev lo

# 运行 http/socks5 服务器
vproxy run -i 2001:470:e953::/48 http

# 启动守护进程（后台运行），需要 sudo
sudo vproxy start -i 2001:470:e953::/48 http

# 重启守护进程，需要 sudo
sudo vproxy restart

# 停止守护进程，需要 sudo
sudo vproxy stop

# 显示守护进程日志
vproxy log

# 显示守护进程状态
vproxy status

# 在线更新
vproxy update

# 测试循环请求
while true; do curl -x http://127.0.0.1:8100 -s https://ifconfig.co -A Mozilla; done
...
2001:470:e953:5b75:c862:3328:3e8f:f4d1
2001:470:e953:b84d:ad7d:7399:ade5:4c1c
2001:470:e953:4f88:d5ca:84:83fd:6faa
2001:470:e953:29f3:41e2:d3f2:4a49:1f22
2001:470:e953:98f6:cb40:9dfd:c7ab:18c4
2001:470:e953:f1d7:eb68:cc59:b2d0:2c6f
```

## 高级用法

- TTL 扩展

在用户名后附加 `-ttl-`，其中 TTL 是一个固定值（例如 `username-ttl-2`）。TTL 值是可以使用相同 IP 进行请求的次数。当达到 TTL 值时，IP 将被更改。

- Session 扩展

在用户名后附加 `-session-id`，其中 session 是固定值，ID 是任意随机值（例如 `username-session-123456`）。保持 Session ID 不变以使用固定 IP。

- Range 扩展

在用户名后附加 `-range-id`，其中 range 是固定值，ID 是任意随机值（例如 `username-range-123456`）。通过保持 Range ID 不变，您可以在固定范围内使用固定 CIDR 范围。此外，您必须设置启动参数 `--cidr-range`，且长度在有效范围内。



### 示例

- 带用户名和密码的 Http 代理会话：

```shell
vproxy run --bind 127.0.0.1:8101 -i 2001:470:70c6::/48 http -u test -p test

$ for i in `seq 1 10`; do curl -x "http://test-session-123456789:test@127.0.0.1:8101" -L v6.ipinfo.io; done
2001:470:70c6:93ee:9b7c:b4f9:4913:22f5
2001:470:70c6:93ee:9b7c:b4f9:4913:22f5
2001:470:70c6:93ee:9b7c:b4f9:4913:22f5

$ for i in `seq 1 10`; do curl -x "http://test-session-987654321:test@127.0.0.1:8101" -L v6.ipinfo.io; done
2001:470:70c6:41d0:14fd:d025:835a:d102
2001:470:70c6:41d0:14fd:d025:835a:d102
2001:470:70c6:41d0:14fd:d025:835a:d102
```

- 带用户名和密码的 Socks5 代理会话：

```shell
vproxy run --bind 127.0.0.1:8101 -i 2001:470:70c6::/48 socks5 -u test -p test

$ for i in `seq 1 3`; do curl -x "socks5h://test-session-123456789:test@127.0.0.1:8101" -L v6.ipinfo.io; done
2001:470:70c6:93ee:9b7c:b4f9:4913:22f5
2001:470:70c6:93ee:9b7c:b4f9:4913:22f5
2001:470:70c6:93ee:9b7c:b4f9:4913:22f5

$ for i in `seq 1 3`; do curl -x "socks5h://test-session-987654321:test@127.0.0.1:8101" -L v6.ipinfo.io; done
2001:470:70c6:41d0:14fd:d025:835a:d102
2001:470:70c6:41d0:14fd:d025:835a:d102
2001:470:70c6:41d0:14fd:d025:835a:d102
```

- 带用户名和密码的 TTL 代理会话：

```shell
vproxy run --bind 127.0.0.1:8101 -i 2001:470:70c6::/48 socks5 -u test -p test

$ for i in `seq 1 3`; do curl -x "socks5h://test-ttl-2:test@127.0.0.1:8101" -L v6.ipinfo.io; done
2001:470:70c6:93ee:9b7c:b4f9:4913:22f5
2001:470:70c6:93ee:9b7c:b4f9:4913:22f5
2001:470:70c6:93ee:9b7c:b4f9:4913:22f6

$ for i in `seq 1 3`; do curl -x "socks5h://test-ttl-2:test@127.0.0.1:8101" -L v6.ipinfo.io; done
2001:470:70c6:41d0:14fd:d025:835a:d102
2001:470:70c6:41d0:14fd:d025:835a:d102
2001:470:70c6:41d0:14fd:d025:835a:d105
```

### [关于 `socks5h` 和 `socks5` 的 DNS 解析行为](https://github.com/0x676e67/vproxy/issues/41#issuecomment-2111318008)： 引用claude回复
 
> 1. `socks5://` (没有h)：
> * DNS 解析发生在本地客户端
> * 先在本地解析域名（ifconfig.co）得到 IP 地址
> * 然后将这个 IP 地址发送给 SOCKS5 代理服务器
> * 适用于你信任本地 DNS 服务器的情况
> 
> 2. `socks5h://` (带h)：
> * DNS 解析发生在代理服务器端
> * 域名（ifconfig.co）直接发送给 SOCKS5 代理服务器
> * 由代理服务器进行 DNS 解析
> * 更安全，可以避免 DNS 泄漏
> * 适用于需要匿名或者本地 DNS 不可靠的情况
> 
> 实际使用建议：
> * 如果你需要通过代理进行匿名访问，使用 `socks5h://`
> * 如果你更关心访问速度，并且信任本地 DNS，可以使用 `socks5://`
