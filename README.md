# SharpRsat

基于 RSAT **ActiveDirectory** 模块的 AD PowerShell 透传 CLI，并内置常用只读目录侦察预设。

- **目标框架**：.NET Framework 4.8（x64）
- **宿主**：进程内 `System.Management.Automation` Runspace（Windows PowerShell 5.1）

## 环境要求

| 项 | 说明 |
| --- | --- |
| 操作系统 | Windows（Client 或 Server） |
| 运行时 | .NET Framework 4.8 |
| PowerShell | Windows PowerShell 5.1（系统自带即可） |
| RSAT AD | 需本机已有 `ActiveDirectory` 模块；缺失时仅在显式 `--install-rsat` 时安装（需**管理员**） |
| 目录查询 | 需能连通域控，并以有权限的**域凭据**运行 |

## 构建

用 Visual Studio 打开 `SharpRsat.sln`，配置选 **x64**，生成即可。

或使用 MSBuild（需已安装 .NET Framework 4.8 引用程序集 / Targeting Pack）：

```text
msbuild SharpRsat.sln /p:Configuration=Release /p:Platform=x64
```

产物示例路径：`src\SharpRsat\bin\x64\Release\SharpRsat.exe`。

## 用法概览

```text
SharpRsat.exe <AD-Cmdlet> [arguments...]
SharpRsat.exe recon [list|<preset>]
SharpRsat.exe <preset>
SharpRsat.exe -list
SharpRsat.exe -h
```

全局标志（可出现在命令行任意位置，解析后剥离）：

| 标志 | 默认 | 作用 |
| --- | --- | --- |
| `--install-rsat` | 关 | 模块缺失时才允许安装 RSAT AD PowerShell |
| `--allow-write` | 关 | 放行非只读 AD cmdlet（`Set-` / `New-` / `Add-` 等） |
| `--quiet` / `-q` | 关 | 短帮助/仅预设名列表；抑制安装进度输出 |
| `--delay <ms>` | `0` | 每次 PowerShell 调用前休眠（上限 60000） |
| `--max-results <n>` | `0` | 截断写入 stdout 的对象数（`0` = 不限） |

路由规则：

1. 剥离全局标志后，`args[0]` 为 `recon` → `args[1]` 为预设名（缺省或 `list` 则列出预设）
2. `args[0]` 直接匹配预设名/别名（如 `kerberoast`、`da`）→ 执行预设
3. 否则按 ActiveDirectory 模块导出命令白名单透传（默认只读动词）
4. 非 AD cmdlet（如 `Get-Process`）会被拒绝

`-list` / `recon` / `recon list` 仅列出预设，**不**触发 RSAT 安装或模块导入。

## AD 透传

对 `ActiveDirectory` 模块已导出的 cmdlet 做白名单校验后动态调用，支持命名参数与位置参数。  
**默认只读**：允许 `Get-` / `Search-` / `Measure-` / `Test-` / `Find-` 前缀及 `Sync-ADObject`；其它 cmdlet 需 `--allow-write`。

```text
SharpRsat.exe Get-ADUser support
SharpRsat.exe Get-ADUser -Identity support -Properties *
SharpRsat.exe Get-ADGroupMember "Domain Admins"
SharpRsat.exe Get-ADGroupMember -Identity Domain Admins
SharpRsat.exe --allow-write Set-ADUser -Identity support -Description test
```

连续的非命名 token 会按空格拼成一个参数值（兼容 Sliver `execute-assembly` 等会拆掉引号的加载方式）。查询 Domain Admins 也可直接用预设：`da` / `domain-admins`。

结果经 `Out-String` 输出到 stdout；错误写 stderr，失败返回非 0。

## OPSEC / 安全默认

默认行为面向更低噪声与更小误操作面（仍非「隐蔽工具」）：

- **不**自动安装 RSAT；缺失模块时退出并提示 `--install-rsat`
- 透传**默认拒绝写操作**；评估中的变更需显式 `--allow-write`
- 推荐在**已预装** AD 模块的主机上使用：`--quiet --delay <ms>`，并优先窄查询（Filter / Identity），避免短时间连跑全量预设
- `--max-results` 只截断**输出对象数**，不减少目录侧已发出的查询量
- `--quiet -list` 仅打印预设名/别名，不打印用途描述

```text
SharpRsat.exe --quiet --delay 500 da
SharpRsat.exe Get-ADUser -Filter "SamAccountName -eq 'support'" --max-results 20
SharpRsat.exe --install-rsat Get-ADDomain
```

通过 Sliver `execute-assembly` 等加载器时，推荐把数值写在同一 token 里，避免参数被拆坏：

```text
execute-assembly sharprsat.exe -p notepad.exe -- recon dns-records --quiet --delay=5000
execute-assembly sharprsat.exe -p notepad.exe -- recon dns-records --quiet --delay5000
```

## 侦察预设（recon）

全部为只读 `Get-AD*` / LDAP 查询，不包含改密、加组等写操作。

```text
SharpRsat.exe recon list
SharpRsat.exe recon kerberoast
SharpRsat.exe kerberoast
SharpRsat.exe recon domain-admins
SharpRsat.exe da
```

| 预设名（别名） | 用途 |
| --- | --- |
| `domain` | 当前域信息 |
| `forest` | 森林信息 |
| `dcs` | 域控列表 |
| `trusts` | 域信任 |
| `pwdpolicy` | 默认域密码策略 |
| `users` | 启用用户概览 |
| `computers` | 计算机账户（含 OS） |
| `groups` | 组对象 |
| `ous` | OU 结构 |
| `domain-admins` (`da`) | Domain Admins 成员（递归） |
| `enterprise-admins` (`ea`) | Enterprise Admins 成员（递归） |
| `schema-admins` | Schema Admins 成员（递归） |
| `account-operators` | Account Operators 成员（递归） |
| `backup-operators` (`bo`) | Backup Operators 成员（递归） |
| `server-operators` | Server Operators 成员（递归） |
| `print-operators` | Print Operators 成员（递归） |
| `dns-admins` | DnsAdmins 成员（递归） |
| `gpo-creators` | Group Policy Creator Owners 成员（递归） |
| `builtin-admins` | 内置 Administrators 成员（递归） |
| `protected-users` | Protected Users 成员（递归） |
| `admincount` | `adminCount=1` 账户 |
| `fsmo` | FSMO 角色持有者 |
| `sites` | AD 站点 |
| `subnets` | AD 子网 |
| `rodc` | 只读域控 |
| `maq` | 域 `ms-DS-MachineAccountQuota` |
| `dns` (`dns-zones`) | AD 集成 DNS 区域 + 域控 DNS 端点 |
| `dns-records` | AD 集成 DNS 节点名（非墓碑；不解码二进制 RR） |
| `kerberoast` | 可 Kerberoast 用户（含 SPN，排除 krbtgt） |
| `asreproast` | 可 AS-REP Roast 用户（不要求预身份验证） |
| `spn` | 带 SPN 的目录对象 |
| `krbtgt` | krbtgt 账户（`PasswordLastSet` 等） |
| `gmsa` | 托管/组托管服务账户 |
| `unconstrained` | 非约束委派（用户 + 计算机） |
| `constrained` | 约束委派（`msDS-AllowedToDelegateTo`） |
| `rbcd` | 基于资源的约束委派 |
| `trusted-to-auth` (`t2a`) | 协议转换委派（`TrustedToAuthForDelegation`） |
| `pass-never-expires` (`dont-expire`) | 密码永不过期 |
| `pass-not-required` | 允许空密码 |
| `reversible` | 允许可逆密码加密 |
| `des-only` | 仅 DES Kerberos 密钥的账户 |
| `sid-history` | 带 `SIDHistory` 的主体 |
| `disabled-users` | 已禁用用户 |
| `locked-users` (`locked`) | 当前被锁定的用户 |
| `inactive-users` | 启用且 90 天未登录（或从未登录）的用户 |
| `stale-computers` | 启用且 90 天未登录（或从未登录）的计算机 |
| `desc-users` | 描述字段非空用户（常泄密） |
| `info-users` | Notes/`info` 字段非空用户 |
| `scriptpath` | 配置了登录脚本路径的用户 |
| `gpos` | GPO 容器对象 |
| `fine-grained-pwd` (`fgpp`) | 细粒度密码策略（PSO） |
| `laps` | 已配置 LAPS 过期时间的计算机（不导出密码） |
| `bitlocker` | BitLocker 恢复信息对象（仅元数据） |
| `foreign-principals` (`fsp`) | 外来安全主体 |
| `server-computers` | OS 名称含 Server 的计算机 |
| `workstations` | 启用且 OS 不含 Server 的计算机 |
| `legacy-os` | 遗留操作系统计算机（XP/7/2008/2012 等） |

## 管理员权限与域环境

### RSAT 安装（显式）

启动透传或 recon 执行前，程序会检测 `ActiveDirectory` 模块：

1. `Get-Module -ListAvailable ActiveDirectory` 已可用 → 继续
2. 缺失且**未**指定 `--install-rsat` → 非 0 退出，提示该标志
3. 缺失且指定 `--install-rsat`（需**提升权限**）时按系统类型安装：
   - **Server**：`Install-WindowsFeature RSAT-AD-PowerShell`
   - **Client**：`Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0`
4. 安装或导入失败时，会提示权限 / 功能 / 重启等明确错误，并以非 0 退出

已装好模块的普通域用户可做只读查询（权限取决于域 ACL），无需管理员。

### 域连通与凭据

- 查询依赖当前登录（或令牌）身份对域的访问权限；无域凭据、离线或不在可达网络时，多数查询会失败或无结果
- 部分高敏对象（如特权组）可能因 ACL 对低权限账户不可见
- recon 预设只做目录只读枚举，不请求票据、不抓哈希、不导出 BloodHound 图；写操作仅在 `--allow-write` 透传时可能发生

## 范围说明

- 无 GUI；默认文本输出（无 JSON DTO）
- 不封装 DNS / GPO MMC 等其它 RSAT 功能（GPO 仅通过 AD 对象查询）
- 默认不执行写操作；需 `--allow-write` 才放行 AD 模块中的变更类 cmdlet

## 许可与使用注意

仅用于授权的安全评估与运维诊断。在未授权环境中使用可能违法。
