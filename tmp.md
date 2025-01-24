要让 `vproxy` 明确使用指定的子网范围，可以通过调整启动参数和代码来实现更细粒度的控制。以下是步骤和方案：

---

## **1. 使用 `--cidr-range` 控制子网划分**
启动命令中的 `--cidr-range` 参数定义了子网范围。例如：

```bash
vproxy run --bind 127.0.0.1:8101 -i 2001:db8::/32 --cidr-range 64 http -u test -p test
```

- `--cidr-range 64` 将 `/32` 的基础网络划分为多个 `/64` 子网。
- 通过用户名扩展 `-range-ID` 来动态选择子网和主机部分。

**注意：默认情况下，子网选择是动态的，通过 Range ID 哈希计算决定。如果需要指定固定子网，可以通过代码扩展或参数增加限制条件。**

---

## **2. 修改代码以强制使用特定子网**

在 `src/proxy/connect/mod.rs` 中，可以调整 `assign_ipv6_with_range` 和 `assign_ipv4_with_range` 的逻辑，使其支持手动指定子网。例如：

### 修改示例：指定固定子网
在子网计算中增加逻辑，允许手动传入一个目标子网。

```rust
fn assign_ipv6_with_range(
    cidr: &Ipv6Cidr,
    range: u8,
    combined: u128,
    target_subnet: Option<Ipv6Addr>,
) -> Ipv6Addr {
    let base_ip: u128 = match target_subnet {
        Some(subnet) => subnet.into(),
        None => cidr.first_address().into(),
    };
    let prefix_len = cidr.network_length();

    if range < prefix_len {
        return assign_rand_ipv6(cidr);
    }

    let combined_shifted = (combined & ((1u128 << (range - prefix_len)) - 1)) << (128 - range);
    let subnet_mask = !((1u128 << (128 - prefix_len)) - 1);
    let subnet_with_fixed = (base_ip & subnet_mask) | combined_shifted;

    let host_mask = (1u128 << (128 - range)) - 1;
    let host_part: u128 = (random::<u64>() as u128) & host_mask;

    Ipv6Addr::from(subnet_with_fixed | host_part)
}
```

### 调用时传入子网
调用时，可以显式指定目标子网：
```rust
let target_subnet = Some("2001:db8:0:1::".parse::<Ipv6Addr>().unwrap());
let assigned_ip = assign_ipv6_with_range(&cidr, range, combined, target_subnet);
```

---

## **3. 增加命令行参数来指定子网**
为 `vproxy` 增加一个新的启动参数，例如 `--fixed-subnet`，用于明确指定一个子网范围。

### 修改 `BootArgs`
在 `src/main.rs` 的 `BootArgs` 结构中添加一个新的参数：
```rust
/// Fixed subnet for IP allocation, e.g., 2001:db8:0:1::/64
#[clap(long)]
fixed_subnet: Option<Ipv6Cidr>,
```

### 修改 `Connector` 的初始化逻辑
在 `Connector` 的 `new` 方法中增加对 `fixed_subnet` 的支持：
```rust
pub(super) fn new(
    cidr: Option<IpCidr>,
    cidr_range: Option<u8>,
    fallback: Option<IpAddr>,
    connect_timeout: u64,
    fixed_subnet: Option<Ipv6Cidr>, // 新增参数
) -> Self {
    Connector {
        cidr,
        cidr_range,
        fallback,
        connect_timeout: Duration::from_secs(connect_timeout),
        fixed_subnet, // 传入固定子网
        ttl: ttl::TTLCalculator,
    }
}
```

### 修改分配逻辑
在 `assign_ipv6_from_extension` 和 `assign_ipv4_from_extension` 中，优先使用 `fixed_subnet`：
```rust
if let Some(subnet) = self.fixed_subnet {
    return assign_ipv6_with_range(&subnet, range, combined);
}
```

---

## **4. 示例启动命令**
修改后，可以通过 `--fixed-subnet` 参数指定目标子网。例如：
```bash
vproxy run --bind 127.0.0.1:8101 -i 2001:db8::/32 --cidr-range 64 --fixed-subnet 2001:db8:0:1::/64 http -u test -p test
```

- **作用**：
  - 只会从 `2001:db8:0:1::/64` 中分配 IP。
  - Range ID 依然生效，但被限制在此子网范围内。

---

## **5. 不修改代码的方案：通过用户名控制子网**
如果不希望修改代码，也可以通过设计用户名扩展的方式来间接控制子网。例如：

### 用户名扩展约定
- 假设基础网络是 `2001:db8::/32`，每个子网对应一个特定用户名前缀：
  - 子网 `2001:db8::/64`：用户名格式 `username-subnet1-range-ID`
  - 子网 `2001:db8:0:1::/64`：用户名格式 `username-subnet2-range-ID`

### 启动代理
启动代理时：
```bash
vproxy run --bind 127.0.0.1:8101 -i 2001:db8::/32 --cidr-range 64 http -u test -p test
```

### 请求示例
通过用户名扩展明确指定子网：
```bash
curl -x "http://test-subnet1-range-123456:test@127.0.0.1:8101" https://ifconfig.co
```

- 使用 `subnet1`，生成的 IP 仅落在 `2001:db8::/64`。
- 使用 `subnet2`，生成的 IP 仅落在 `2001:db8:0:1::/64`。

---

### **总结**
要让 `vproxy` 使用指定的子网：
1. 最简单的方式是通过用户名扩展间接控制。
2. 如果需要固定逻辑，可以修改代码，引入 `--fixed-subnet` 参数，直接指定目标子网。
3. 修改后的逻辑既支持动态分配，也允许明确限制到特定子网范围。

如果有其他需求，欢迎进一步探讨！
