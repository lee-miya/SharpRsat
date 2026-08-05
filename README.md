# SharpRsat

基于 RSAT **ActiveDirectory** 模块的 AD PowerShell 透传 CLI，并内置红队常用只读侦察预设。

- **目标框架**：.NET Framework 4.8（x64）
- **宿主**：进程内 `System.Management.Automation` Runspace（Windows PowerShell 5.1）

## 环境要求

| 项 | 说明 |
| --- | --- |
| 操作系统 | Windows（Client 或 Server） |
| 运行时 | .NET Framework 4.8 |
| PowerShell | Windows PowerShell 5.1（系统自带即可） |
| RSAT AD | 缺失时程序会尝试自动安装（需**管理员**权限） |
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

路由规则：

1. `args[0]` 为 `recon` → `args[1]` 为预设名（缺省或 `list` 则列出预设）
2. `args[0]` 直接匹配预设名/别名（如 `kerberoast`、`da`）→ 执行预设
3. 否则按 ActiveDirectory 模块导出命令白名单透传
4. 非 AD cmdlet（如 `Get-Process`）会被拒绝

`-list` / `recon` / `recon list` 仅列出预设，**不**触发 RSAT 安装。

## AD 透传

对 `ActiveDirectory` 模块已导出的 cmdlet 做白名单校验后动态调用，支持命名参数与位置参数。

```text
SharpRsat.exe Get-ADUser support
SharpRsat.exe Get-ADUser -Identity support -Properties *
SharpRsat.exe Get-ADGroupMember "Domain Admins"
```

结果经 `Out-String` 输出到 stdout；错误写 stderr，失败返回非 0。

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
| `admincount` | `adminCount=1` 账户 |
| `kerberoast` | 可 Kerberoast 用户（含 SPN，排除 krbtgt） |
| `asreproast` | 可 AS-REP Roast 用户（不要求预身份验证） |
| `spn` | 带 SPN 的目录对象 |
| `unconstrained` | 非约束委派（用户 + 计算机） |
| `constrained` | 约束委派（`msDS-AllowedToDelegateTo`） |
| `rbcd` | 基于资源的约束委派 |
| `pass-never-expires` (`dont-expire`) | 密码永不过期 |
| `pass-not-required` | 允许空密码 |
| `desc-users` | 描述字段非空用户（常泄密） |
| `gpos` | GPO 容器对象 |
| `server-computers` | OS 名称含 Server 的计算机 |

## 管理员权限与域环境

### RSAT 自动安装

启动透传或 recon 执行前，程序会检测 `ActiveDirectory` 模块：

1. `Get-Module -ListAvailable ActiveDirectory` 已可用 → 跳过安装
2. 缺失时按系统类型安装（需**提升权限**）：
   - **Server**：`Install-WindowsFeature RSAT-AD-PowerShell`
   - **Client**：`Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0`
3. 安装或导入失败时，会提示权限 / 功能 / 重启等明确错误，并以非 0 退出

未提升权限时，若本机尚未安装 RSAT AD PowerShell，安装步骤会失败；已装好模块的普通域用户仍可做只读查询（权限取决于域 ACL）。

### 域连通与凭据

- 查询依赖当前登录（或令牌）身份对域的访问权限；无域凭据、离线或不在可达网络时，多数查询会失败或无结果
- 部分高敏对象（如特权组）可能因 ACL 对低权限账户不可见
- 本工具只做目录只读枚举，不请求票据、不抓哈希、不导出 BloodHound 图

## 范围说明

- 无 GUI；默认文本输出（无 JSON DTO）
- 不封装 DNS / GPO MMC 等其它 RSAT 功能（GPO 仅通过 AD 对象查询）
- 首版不含写操作类红队动作（如加组成员）

## 许可与使用注意

仅用于授权的安全评估与运维诊断。在未授权环境中使用可能违法。
