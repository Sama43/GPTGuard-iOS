# GPTGuard-iOS

ChatGPT 降智检测 + IP 纯净度 / 时区检测 + 官方 ChatGPT 客户端「只走代理」黑洞守护（iOS 17+）。

推送到 GitHub 后由 Actions（`macos-26` 运行器）自动编译出 **无签名 IPA**，自行签名安装。

## 功能

| 功能 | 说明 |
|---|---|
| 降智检测（PoW） | 「检测 › 打开网页版 ChatGPT 实测」。App 内置网页版注入脚本，读取 `sentinel/chat-requirements` 响应里的 `proofofwork.difficulty`：有效位 ≥5 正常、4 一般、3 偏高、≤2 高风险/大概率降智。同时记录是否要求 Turnstile / Arkose 人机验证。网页版用**独立数据存储**，与 Safari 隔离。 |
| IP 出口纯净度 | 通过 `chatgpt.com/cdn-cgi/trace` 拿到 **ChatGPT 实际看到的 IP**，再查 `api.ipapi.is` 信誉库（机房 / VPN / 代理 / Tor / 滥用），按社区经验从 100 分往下扣分。 |
| 时区一致性 | 比对 IP 所在时区与本机时区；出口 IP 变化后自动检测，不吻合时弹窗提示。 |
| 黑洞守护（只走代理） | 基于 `NEPacketTunnelProvider` + sing-box 1.14.4。ChatGPT / OpenAI 域名只能经 `guard` 选择器出站：默认是黑洞 `sealed`，出口经代理校验通过后才切到节点，**任何情况下都不会回落直连**。 |
| 直连检测立即掐断 | 扩展进程在隧道外探测本机直连 IP，若 ChatGPT 看到的出口 IP 与之相同（节点没生效 / 直连泄露）立即切回黑洞并持续重检，恢复后自动放行。巡检失败、断网、Wi-Fi/5G 切换、出口落在禁止地区（默认 CN/HK/MO/RU/BY/KP/IR/SY/CU）也会立即封锁。 |
| 断开自动重连 | 可选 On-Demand：隧道崩溃或重启手机后由系统自动拉起，避免无保护时直连。 |
| 节点 / 机场订阅导入 | 剪贴板或手动粘贴：`vless://` `vmess://` `trojan://` `ss://` `hysteria2://` / `hy2://` `tuic://` `socks5://` `http(s)://`、Clash/Mihomo YAML、V2Ray Base64、sing-box JSON。机场订阅（HTTPS）自动识别格式并显示已用流量。 |

### 分流模式

- **默认（仅接管 ChatGPT）**：只有 OpenAI / ChatGPT 相关域名（FakeIP + 远程 DoH，防 DNS 泄露）走代理和黑洞，其他 App 直连。
- **全局模式**：整机流量走代理，熔断时整机黑洞。

## 用 GitHub Actions 编译 IPA

1. 在 GitHub 新建一个仓库（建议 **Private**），把本目录推上去：
   ```bash
   git remote add origin https://github.com/<你的用户名>/GPTGuard-iOS.git
   git push -u origin main
   ```
2. 推送到 `main` 会自动触发 **Actions › Build GPTGuard iOS IPA**；也可在 Actions 页面点 *Run workflow* 手动运行。
3. 约 15–25 分钟后（首次需编译 sing-box，之后有缓存会快很多），在运行详情底部的 **Artifacts** 下载 `GPTGuard-iOS-IPA`，解压得到 `GPTGuard-iOS-v1.0.0-unsigned.ipa`。
4. 打 `v*` 标签（如 `git tag v1.0.0 && git push --tags`）会额外发布到 Releases。

编译失败时，`Build Unsigned Release` 步骤末尾会打印 `ERROR SUMMARY`，把那段日志发给 Claude 即可继续修。

## 签名安装（重要）

VPN 守护依赖 **Network Extension（packet-tunnel-provider）** 权限：

- ✅ TrollStore（巨魔）、付费开发者账号 / 企业证书重签（爱思助手、ESign、Sideloadly + 付费账号等），需同时给主 App 和 `PlugIns/PacketTunnel.appex` 签名并保留 Network Extension 权限。
- ❌ 免费 Apple ID 无法签 Network Extension —— 这种情况下「检测」页（PoW 降智、纯净度、时区）仍可用，但无法开启 VPN 守护。
- App Group 不可用时会自动降级为直传配置 + 本地鉴权通道，重签改 Bundle ID 也能工作。

## 使用流程

1. **节点** 页：添加机场订阅或从剪贴板导入节点 → 点「测速」看出口地区。
2. 点「以此节点隔离官方 ChatGPT」→ 系统弹出添加 VPN 配置时允许。
3. **守护** 页变绿（已校验出口）后，点「安全启动官方 ChatGPT iOS 客户端」。
4. **检测** 页查看纯净度、时区；打开网页版发一条消息拿到 PoW 结果，这是判断降智最准的指标。

## 局限

- 降智是服务器端决定的，App 只能**检测**并帮你避免直连 / 换到更干净的出口，不能「解除」降智。
- iOS 沙盒无法读取官方 ChatGPT App 的内部流量，所以用 App 内网页版代测（同一出口）。
- PoW 阈值与 IP 评分规则是社区经验，不是 OpenAI 官方标准；`chat-requirements` 接口字段将来可能变化。
- 在网页版用 Google 账号登录可能被拦截（disallowed_useragent），可改用邮箱或 Apple 登录。

## 目录结构

```
AppSources/            主 App（SwiftUI）
  Diagnostics/         IP 纯净度、时区、PoW 降智检测、网页版 ChatGPT
  Views/               守护 / 检测 / 身份 / 节点 / 审计 五个页面
TunnelSources/         PacketTunnel 扩展（巡检、黑洞熔断、直连泄露检测）
Shared/                两个 target 共用：模型、sing-box 配置生成、出口校验
corebridge/            Go：sing-box 1.14.4 桥接（gomobile 编成 Corebridge.xcframework）
project.yml            XcodeGen 工程描述（CI 中生成 .xcodeproj）
.github/workflows/     CI：编译 sing-box → XcodeGen → xcodebuild → 打包 IPA
```

隧道与黑洞架构沿用 ClaudeAppGuard-iOS，在其基础上改为面向 ChatGPT，并新增降智 / 纯净度 / 时区检测与直连泄露检测。
