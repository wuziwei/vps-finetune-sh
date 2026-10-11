#!/usr/bin/env bash
# ==============================================================================
# Oracle Cloud / Linux VPS 状态诊断与一键调优加固工具
# 流程：系统状态采集 -> 逐项对比与建议 -> 交互确认(需输入yes) -> 幂等优化与验证
# ==============================================================================

set -u

# 颜色常量
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
CYAN="\033[36m"
BOLD="\033[1m"
PLAIN="\033[0m"

# 1. 基础权限检测
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[-] 错误：必须使用 root 权限执行此脚本！(sudo -i)${PLAIN}" >&2
    exit 1
fi

echo -e "${CYAN}======================================================================${PLAIN}"
echo -e "${BOLD}       甲骨文云 / Linux VPS 系统健康诊断与推荐调优 (检查阶段)       ${PLAIN}"
echo -e "${CYAN}======================================================================${PLAIN}"

# 2. 硬件与架构识别
ARCH=$(uname -m)
MEM_TOTAL_KB=$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}' || echo 0)
MEM_TOTAL_MB=$((MEM_TOTAL_KB / 1024))

if [ "$ARCH" = "aarch64" ]; then
    MACHINE_TYPE="ARM 实例 (多核大内存)"
    REC_RMEM=67108864
    REC_CONN_MAX=1048576
else
    MACHINE_TYPE="AMD / 通用实例"
    REC_RMEM=33554432
    REC_CONN_MAX=524288
fi

echo -e "机器平台 : ${BOLD}$ARCH${PLAIN} (${GREEN}$MACHINE_TYPE${PLAIN}) | 内存总计: ${BOLD}${MEM_TOTAL_MB} MB${PLAIN}"
echo -e "正在收集系统配置与内核运行参数，请稍候...\n"

# ------------------------------------------------------------------------------
# 3. 逐项指标采集
# ------------------------------------------------------------------------------
NEED_FIX_COUNT=0
declare -a FIX_ITEMS=()

check_item() {
    local name="$1"
    local current="$2"
    local target="$3"
    local is_ok="$4"
    local fix_desc="$5"

    if [ "$is_ok" = "1" ]; then
        printf " %-26s | %-16s | %-16s | ${GREEN}[已达标]${PLAIN}\n" "$name" "$current" "$target"
    else
        printf " %-26s | %-16s | %-16s | ${YELLOW}[需优化]${PLAIN}\n" "$name" "$current" "$target"
        NEED_FIX_COUNT=$((NEED_FIX_COUNT + 1))
        FIX_ITEMS+=("$fix_desc")
    fi
}

# 格式化输出表头
echo -e "----------------------------------------------------------------------"
printf " ${BOLD}%-26s | %-16s | %-16s | 状态${PLAIN}\n" "检测项目" "当前配置" "推荐标准"
echo -e "----------------------------------------------------------------------"

# [项 1] TCP 拥塞控制算法
CUR_CC=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")
[ "$CUR_CC" = "bbr" ] && OK=1 || OK=0
check_item "TCP 拥塞控制 (cc)" "$CUR_CC" "bbr" "$OK" "启用 BBR 拥塞控制算法"

# [项 2] 队列调度算法
CUR_QDISC=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "unknown")
[ "$CUR_QDISC" = "fq" ] && OK=1 || OK=0
check_item "网卡队列调度 (qdisc)" "$CUR_QDISC" "fq" "$OK" "设置默认队列算法为 fq"

# [项 3] UDP 接收缓冲上限 (rmem_max)
CUR_RMEM=$(sysctl -n net.core.rmem_max 2>/dev/null || echo "0")
[ "$CUR_RMEM" -ge "$REC_RMEM" ] && OK=1 || OK=0
check_item "UDP 接收缓冲 (rmem_max)" "$CUR_RMEM" ">= $REC_RMEM" "$OK" "优化 UDP 接收/发送缓冲区大小 (适配 Hysteria 2)"

# [项 4] 连接跟踪表上限 (conntrack)
CUR_CONN=$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo "0")
[ "$CUR_CONN" -ge "$REC_CONN_MAX" ] && OK=1 || OK=0
check_item "连接跟踪上限 (conn_max)" "$CUR_CONN" ">= $REC_CONN_MAX" "$OK" "调大 nf_conntrack 容量，缩短 UDP 超时防撑爆"

# [项 5] 文件打开数硬限制 (LimitNOFILE)
CUR_NOFILE=$(ulimit -Hn 2>/dev/null || echo "1024")
[ "$CUR_NOFILE" -ge 1048576 ] && OK=1 || OK=0
check_item "系统文件句柄 (nofile)" "$CUR_NOFILE" ">= 1048576" "$OK" "提高全局与 systemd 进程文件句柄上限至 1048576"

# [项 6] SSH 认证重试限制 (MaxAuthTries)
CUR_TRIES=$(grep -E "^[# ]*MaxAuthTries" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "6")
[ "$CUR_TRIES" = "3" ] && OK=1 || OK=0
check_item "SSH 最大认证尝试" "${CUR_TRIES:-6}" "3" "$OK" "将 SSH 最大认证重试次数限制为 3 次"

# [项 7] Fail2ban 防爆破保护
if systemctl is-active --quiet fail2ban 2>/dev/null; then
    F2B_STAT="运行中"; OK=1
else
    F2B_STAT="未运行"; OK=0
fi
check_item "Fail2ban 防爆破服务" "$F2B_STAT" "运行中" "$OK" "部署 Fail2ban (输错 3 次自动拉黑 24 小时)"

# [项 8] IPv4 端口跳跃 (20000:50000 -> 2053)
if iptables -t nat -C PREROUTING -p udp --dport 20000:50000 -j REDIRECT --to-ports 2053 >/dev/null 2>&1; then
    V4_HOP="已生效"; OK=1
else
    V4_HOP="未配置"; OK=0
fi
check_item "IPv4 端口跳跃" "$V4_HOP" "已生效" "$OK" "配置 IPv4 UDP 端口跳跃 (20000:50000 -> 2053) 并放行防火墙"

# [项 9] IPv6 端口跳跃 (20000:50000 -> 2053)
if ip6tables -t nat -C PREROUTING -p udp --dport 20000:50000 -j REDIRECT --to-ports 2053 >/dev/null 2>&1; then
    V6_HOP="已生效"; OK=1
else
    V6_HOP="未配置"; OK=0
fi
check_item "IPv6 端口跳跃" "$V6_HOP" "已生效" "$OK" "配置 IPv6 UDP 端口跳跃与转发，补齐双栈跳跃通路"

# [项 10] update-singbox 工具部署
if [ -x "/usr/local/bin/update-singbox" ]; then
    SB_TOOL="已安装"; OK=1
else
    SB_TOOL="未安装"; OK=0
fi
check_item "sing-box 版本管理工具" "$SB_TOOL" "已安装" "$OK" "部署 /usr/local/bin/update-singbox 一键升级/回滚脚本"

# [项 11] DNS 锁定防 DHCP 篡改
if lsattr /etc/resolv.conf 2>/dev/null | grep -q -- "-i-"; then
    DNS_LOCK="已锁定(+i)"; OK=1
else
    DNS_LOCK="未锁定"; OK=0
fi
check_item "DNS 优选与防篡改锁定" "$DNS_LOCK" "已锁定(+i)" "$OK" "测速优选 Cloudflare/Google DNS 并锁定防 DHCP 覆盖"

# [项 12] 甲骨文云 Agent (仅 AMD 1G 提示)
if [ "$ARCH" != "aarch64" ]; then
    if systemctl is-active --quiet oracle-cloud-agent 2>/dev/null; then
        AGENT_STAT="运行中(占内存)"; OK=0
    else
        AGENT_STAT="已停止/卸载"; OK=1
    fi
    check_item "甲骨文后台监控 Agent" "$AGENT_STAT" "已停用" "$OK" "停止并禁用 oracle-cloud-agent (释放约 100~200MB 内存)"
fi

echo -e "----------------------------------------------------------------------"

# ------------------------------------------------------------------------------
# 4. 汇总与优化建议清单
# ------------------------------------------------------------------------------
echo ""
if [ "$NEED_FIX_COUNT" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}🎉 恭喜！当前系统所有关键指标均已达到推荐最优配置，无需做任何变更。${PLAIN}"
    exit 0
fi

echo -e "${YELLOW}${BOLD}📌 诊断发现共有 $NEED_FIX_COUNT 项配置需要优化。建议执行的调整清单如下：${PLAIN}"
index=1
for desc in "${FIX_ITEMS[@]}"; do
    echo -e "  ${CYAN}${index}.${PLAIN} $desc"
    index=$((index + 1))
done

echo ""
echo -e "${BOLD}确认提示：即将执行上述优化建议项。${PLAIN}"
echo ""

# ------------------------------------------------------------------------------
# 5. 交互输入校验
# ------------------------------------------------------------------------------
CONFIRM=""
if [ -t 0 ]; then
    read -r -p "是否立即应用上述优化？请输入 [yes] 确认执行 (输入其它任意键退出): " CONFIRM
else
    read -r -p "是否立即应用上述优化？请输入 [yes] 确认执行 (输入其它任意键退出): " CONFIRM < /dev/tty
fi

if [ "$CONFIRM" != "yes" ] && [ "$CONFIRM" != "YES" ]; then
    echo -e "\n${YELLOW}[!] 操作已取消，系统配置未做任何修改。${PLAIN}"
    exit 0
fi

echo -e "\n${GREEN}[+] 已获得确认，开始执行系统优化与安全加固...${PLAIN}\n"

# ------------------------------------------------------------------------------
# 6. 执行优化动作
# ------------------------------------------------------------------------------

# 步骤 A：安装必要组件
echo -e "${CYAN}[1/6] 正在安装必要网络与系统组件...${PLAIN}"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && apt-get install -y -qq \
    curl jq tar iptables iptables-persistent fail2ban \
    dnsutils conntrack libcap2-bin python3 >/dev/null 2>&1 || true

# 步骤 B：内核网络、BBR、缓冲区
echo -e "${CYAN}[2/6] 应用内核网络参数与 BBR 优化...${PLAIN}"
modprobe nf_conntrack 2>/dev/null || true
echo "nf_conntrack" > /etc/modules-load.d/conntrack.conf

if [ "$ARCH" = "aarch64" ]; then
    RMEM_MAX=67108864; WMEM_MAX=67108864; RMEM_DEF=4194304; WMEM_DEF=4194304
    BACKLOG=30000; SOMAXCONN=65535; UDP_MEM="131072 262144 524288"; CONN_MAX=1048576
else
    RMEM_MAX=33554432; WMEM_MAX=33554432; RMEM_DEF=2097152; WMEM_DEF=2097152
    BACKLOG=32768; SOMAXCONN=32768; UDP_MEM="65536 131072 262144"; CONN_MAX=524288
fi

cat << SYSCTL_EOF > /etc/sysctl.d/99-network-optimize.conf
# 文件句柄
fs.file-max = 2097152

# HY2 / UDP 缓冲
net.core.rmem_max = $RMEM_MAX
net.core.wmem_max = $WMEM_MAX
net.core.rmem_default = $RMEM_DEF
net.core.wmem_default = $WMEM_DEF
net.core.netdev_max_backlog = $BACKLOG
net.core.somaxconn = $SOMAXCONN
net.ipv4.udp_mem = $UDP_MEM

# Conntrack 连接跟踪
net.netfilter.nf_conntrack_max = $CONN_MAX
net.netfilter.nf_conntrack_udp_timeout = 30
net.netfilter.nf_conntrack_udp_timeout_stream = 120

# BBR & TCP
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_mtu_probing = 0

# IPv6 转发支持
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1
SYSCTL_EOF

sysctl --system >/dev/null 2>&1

# 文件句柄限制
cat << 'LIMITS_EOF' > /etc/security/limits.d/99-nofile.conf
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
LIMITS_EOF

sed -i 's/^#\?DefaultLimitNOFILE=.*/DefaultLimitNOFILE=1048576/g' /etc/systemd/system.conf 2>/dev/null || true
sed -i 's/^#\?DefaultLimitNOFILE=.*/DefaultLimitNOFILE=1048576/g' /etc/systemd/user.conf 2>/dev/null || true

mkdir -p /etc/systemd/system/sing-box.service.d/
cat << 'SB_LIMIT' > /etc/systemd/system/sing-box.service.d/override.conf
[Service]
LimitNOFILE=1048576
LimitNPROC=512000
SB_LIMIT
systemctl daemon-reload >/dev/null 2>&1 || true

# 步骤 C：双栈 DNS 测速与固化
echo -e "${CYAN}[3/6] 测速写入 Cloudflare/Google DNS 并锁定防覆写...${PLAIN}"
bench_dns() {
    local ip=$1
    local total=0 count=0
    for d in "www.apple.com" "www.bing.com"; do
        local t
        t=$(dig @"$ip" "$d" +tries=1 +time=2 +stats 2>/dev/null | awk '/Query time:/ {print $4}' || true)
        if [[ -n "$t" && "$t" =~ ^[0-9]+$ ]]; then
            total=$((total + t))
            count=$((count + 1))
        fi
    done
    [ $count -gt 0 ] && echo $((total / count)) || echo "-1"
}

CF4_MS=$(bench_dns "1.1.1.1")
G4_MS=$(bench_dns "8.8.8.8")
CF6_MS=$(bench_dns "2606:4700:4700::1111")
G6_MS=$(bench_dns "2001:4860:4860::8888")

[ "$CF4_MS" -ge 0 ] && { [ "$G4_MS" -lt 0 ] || [ "$CF4_MS" -le "$G4_MS" ]; } && { P_V4="1.1.1.1"; B_V4="8.8.8.8"; } || { P_V4="8.8.8.8"; B_V4="1.1.1.1"; }

HAS_V6=false
if [ "$CF6_MS" -ge 0 ] || [ "$G6_MS" -ge 0 ]; then
    HAS_V6=true
    [ "$CF6_MS" -ge 0 ] && { [ "$G6_MS" -lt 0 ] || [ "$CF6_MS" -le "$G6_MS" ]; } && { P_V6="2606:4700:4700::1111"; B_V6="2001:4860:4860::8888"; } || { P_V6="2001:4860:4860::8888"; B_V6="2606:4700:4700::1111"; }
fi

chattr -i /etc/resolv.conf 2>/dev/null || true
rm -f /etc/resolv.conf
{
    echo "# Configured by VPS Optimizer"
    echo "nameserver $P_V4"
    [ "$HAS_V6" = true ] && echo "nameserver $P_V6"
    echo "nameserver $B_V4"
    [ "$HAS_V6" = true ] && echo "nameserver $B_V6"
    echo "options timeout:2 attempts:3 rotate"
} > /etc/resolv.conf
chattr +i /etc/resolv.conf 2>/dev/null || true

# 步骤 D：IPv4 & IPv6 双栈端口跳跃
echo -e "${CYAN}[4/6] 配置 IPv4/IPv6 双栈端口跳跃 (20000:50000 -> 2053)...${PLAIN}"
# IPv4
iptables -t nat -C PREROUTING -p udp --dport 20000:50000 -j REDIRECT --to-ports 2053 >/dev/null 2>&1 || \
    iptables -t nat -I PREROUTING 1 -p udp --dport 20000:50000 -j REDIRECT --to-ports 2053
iptables -C INPUT -p udp --dport 2053 -j ACCEPT >/dev/null 2>&1 || \
    iptables -I INPUT 1 -p udp --dport 2053 -j ACCEPT
iptables -C INPUT -p udp --dport 20000:50000 -j ACCEPT >/dev/null 2>&1 || \
    iptables -I INPUT 1 -p udp --dport 20000:50000 -j ACCEPT

# IPv6
ip6tables -t nat -C PREROUTING -p udp --dport 20000:50000 -j REDIRECT --to-ports 2053 >/dev/null 2>&1 || \
    ip6tables -t nat -I PREROUTING 1 -p udp --dport 20000:50000 -j REDIRECT --to-ports 2053
ip6tables -C INPUT -p udp --dport 2053 -j ACCEPT >/dev/null 2>&1 || \
    ip6tables -I INPUT 1 -p udp --dport 2053 -j ACCEPT
ip6tables -C INPUT -p udp --dport 20000:50000 -j ACCEPT >/dev/null 2>&1 || \
    ip6tables -I INPUT 1 -p udp --dport 20000:50000 -j ACCEPT

netfilter-persistent save >/dev/null 2>&1 || true

# 步骤 E：SSH 加固与 Fail2ban (仅限重试限制与防爆破，不关密码登录)
echo -e "${CYAN}[5/6] 配置 SSH 重试限制与 Fail2ban 自动封禁...${PLAIN}"
sed -i -E 's/^#?MaxAuthTries .*/MaxAuthTries 3/' /etc/ssh/sshd_config
if ! grep -q "^MaxAuthTries" /etc/ssh/sshd_config; then
    echo "MaxAuthTries 3" >> /etc/ssh/sshd_config
fi

if sshd -t 2>/dev/null; then
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
fi

# 写入 Fail2ban 规则
mkdir -p /etc/fail2ban
cat << 'EOF' > /etc/fail2ban/jail.local
[DEFAULT]
bantime = 86400
findtime = 600
maxretry = 3
backend = systemd

[sshd]
enabled = true
port = ssh
EOF

systemctl daemon-reload >/dev/null 2>&1 || true
systemctl restart fail2ban >/dev/null 2>&1 || true
systemctl enable fail2ban >/dev/null 2>&1 || true

# 步骤 F：标准化部署 update-singbox
echo -e "${CYAN}[6/6] 部署 /usr/local/bin/update-singbox 管理工具...${PLAIN}"
cat << 'EOF' > /usr/local/bin/update-singbox
#!/usr/bin/env bash
set -e
if [ "$(id -u)" -ne 0 ]; then
    echo "[-] 错误：必须使用 root 权限执行此脚本: sudo update-singbox" >&2
    exit 1
fi
RAW_ARCH=$(uname -m)
case "$RAW_ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "[-] 不支持的架构: $RAW_ARCH" >&2; exit 1 ;;
esac
command -v jq &>/dev/null || apt-get install -y -qq jq >/dev/null 2>&1 || true
command -v curl &>/dev/null || apt-get install -y -qq curl >/dev/null 2>&1 || true
command -v tar &>/dev/null || apt-get install -y -qq tar >/dev/null 2>&1 || true
CURRENT_VER=$(sing-box version 2>/dev/null | head -n 1 | awk '{print $3}' || echo "未安装")
echo "📡 正在从 GitHub Releases 获取版本列表..."
RELEASES_JSON=$(curl -sSL -m 15 -H "User-Agent: Mozilla/5.0" "https://api.github.com/repos/SagerNet/sing-box/releases?per_page=20" || true)
if [ -z "$RELEASES_JSON" ] || ! echo "$RELEASES_JSON" | jq -e '.[0]' >/dev/null 2>&1; then
    echo "[-] 获取 GitHub Releases 失败，请检查网络或是否受到 API 限制。" >&2; exit 1
fi
LATEST_STABLE=$(echo "$RELEASES_JSON" | jq -r '[.[] | select(.prerelease == false)][0].tag_name')
LATEST_PRERELEASE=$(echo "$RELEASES_JSON" | jq -r '[.[] | select(.prerelease == true)][0].tag_name')
echo ""
echo "========================================="
echo "        VPS sing-box 版本管理工具"
echo "========================================="
echo " 📌 本机当前版本:    $CURRENT_VER"
echo " 🟢 官方最新正式版:  $LATEST_STABLE"
echo " 🟠 官方最新测试版:  $LATEST_PRERELEASE"
echo "========================================="
echo "快捷升级通道:"
echo "  1) 安装/切换为 最新测试版 ($LATEST_PRERELEASE) [默认]"
echo "  2) 安装/切换为 最新正式版 ($LATEST_STABLE)"
echo ""
echo "--- 更多可用历史版本 ---"
declare -A TAG_MAP
TAG_MAP[1]="$LATEST_PRERELEASE"
TAG_MAP[2]="$LATEST_STABLE"
INDEX=3
while IFS=$'\t' read -r TAG PRERELEASE; do
    [ -z "$TAG" ] && continue
    [ "$PRERELEASE" = "true" ] && TYPE_LABEL="(测试版)" || TYPE_LABEL="(正式版)"
    TAG_MAP[$INDEX]="$TAG"
    printf "  %2d) 安装版本 %-18s %s\n" "$INDEX" "$TAG" "$TYPE_LABEL"
    INDEX=$((INDEX + 1))
    [ $INDEX -gt 12 ] && break
done < <(echo "$RELEASES_JSON" | jq -r '.[] | [.tag_name, .prerelease] | @tsv')
echo "   0) 退出"
echo "========================================="
read -r -p "请输入选项编号 (或直接按回车安装测试版) [默认 1]: " CHOICE < /dev/tty
CHOICE=${CHOICE:-1}
[ "$CHOICE" = "0" ] && echo "[+] 已退出。" && exit 0
SELECTED_TAG="${TAG_MAP[$CHOICE]}"
[ -z "$SELECTED_TAG" ] && echo "[-] 无效选项！" && exit 1
echo ""
echo "[+] 准备安装版本: $SELECTED_TAG (架构: linux-$ARCH)"
ASSET_URL=$(echo "$RELEASES_JSON" | jq -r --arg tag "$SELECTED_TAG" --arg arch "linux-$ARCH" '
    .[] | select(.tag_name == $tag) | .assets[] | select(.name | test("sing-box-.*-" + $arch + "\\.tar\\.gz$")) | .browser_download_url
' | head -n 1)
if [ -z "$ASSET_URL" ] || [ "$ASSET_URL" = "null" ]; then
    echo "[-] 未找到适用于架构 linux-$ARCH 的安装包！" >&2; exit 1
fi
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT
echo "[+] 正在下载: $ASSET_URL ..."
curl -L --progress-bar -o "$TMP_DIR/sing-box.tar.gz" "$ASSET_URL"
echo "[+] 正在解压并部署..."
tar -xzf "$TMP_DIR/sing-box.tar.gz" -C "$TMP_DIR"
BIN_PATH=$(find "$TMP_DIR" -type f -name "sing-box" | head -n 1)
chmod +x "$BIN_PATH"
cp -f "$BIN_PATH" /usr/local/bin/sing-box
ln -sf /usr/local/bin/sing-box /usr/bin/sing-box
if systemctl is-active --quiet sing-box 2>/dev/null; then
    echo "[+] 重启 sing-box 服务..."
    systemctl restart sing-box
fi
echo "========================================="
echo "🎉 安装/切换完成！当前版本信息："
sing-box version
echo "========================================="
EOF
chmod +x /usr/local/bin/update-singbox
hash -r 2>/dev/null || true

# AMD 机型停用 Agent
if [ "$ARCH" != "aarch64" ] && systemctl is-active --quiet oracle-cloud-agent 2>/dev/null; then
    systemctl stop oracle-cloud-agent >/dev/null 2>&1 || true
    systemctl disable oracle-cloud-agent >/dev/null 2>&1 || true
fi

echo ""
echo -e "${GREEN}======================================================================${PLAIN}"
echo -e "${GREEN}${BOLD}🎉 所有推荐优化与安全加固已成功执行完毕！${PLAIN}"
echo -e "${GREEN}======================================================================${PLAIN}"
echo -e "提示："
echo -e " 1. 双栈端口跳跃已全部激活，并已持久化保存 (重启不丢失)。"
echo -e " 2. Fail2ban 已运行，可执行 ${BOLD}fail2ban-client status sshd${PLAIN} 观察拦截。"
echo -e " 3. 可在终端直接输入 ${BOLD}update-singbox${PLAIN} 随时管理 sing-box 内核版本。"
