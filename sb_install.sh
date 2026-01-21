#!/bin/bash

# ====================================================
# Sing-box 全能安装脚本 (VLESS-RealTLS + Hysteria2 + ShadowTLS)
# 版本: v3.5 (针对 Windows Clash 增加 skip-cert-verify 和 UDP)
# 适配系统: Ubuntu 20.04 / 22.04 / 24.04
# ====================================================

# 颜色定义
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
PLAIN='\033[0m'

# 配置文件路径
SB_CONFIG="/etc/sing-box/config.json"
CERT_DIR="/etc/sing-box/cert"
NGINX_CONF="/etc/nginx/conf.d/singbox_fallback.conf"

# ShadowTLS 伪装目标 (必须是服务端能访问的网站)
HANDSHAKE_SERVER="www.microsoft.com"

check_root() {
    if [ $EUID -ne 0 ]; then
        echo -e "${RED}错误: 请使用 root 权限运行此脚本！${PLAIN}"
        echo -e "请尝试运行: sudo -i 切换到 root 用户后再运行。"
        exit 1
    fi
}

install_dependencies() {
    echo -e "${YELLOW}正在安装必要依赖 (含 jq, qrencode)...${PLAIN}"
    apt update -y
    # 增加 jq 以精确解析配置文件
    # 增加 qrencode 以生成二维码
    apt install -y curl wget socat nginx tar openssl jq ufw qrencode
    systemctl stop nginx
}

install_singbox() {
    echo -e "${YELLOW}正在安装 Sing-box...${PLAIN}"
    # 修复：使用管道代替进程替换，兼容 sh/dash
    curl -fsSL https://sing-box.app/deb-install.sh | bash
    systemctl enable sing-box
}

get_cert() {
    echo -e "${YELLOW}正在检查 SSL 证书...${PLAIN}"
    if [ -z "$DOMAIN" ]; then
        echo -e "${RED}域名为空，跳过证书申请${PLAIN}"
        return
    fi

    # 智能检测：如果证书已存在且匹配当前域名，则跳过申请
    if [ -f "$CERT_DIR/fullchain.crt" ] && [ -f "$CERT_DIR/private.key" ]; then
        # 使用 openssl 检查证书中的 DNS 名称是否包含当前域名
        if openssl x509 -in "$CERT_DIR/fullchain.crt" -noout -text | grep -q "DNS:${DOMAIN}"; then
            echo -e "${GREEN}检测到域名 ${DOMAIN} 的有效证书，跳过申请步骤。${PLAIN}"
            return
        else
            echo -e "${YELLOW}现有证书域名不匹配，准备重新申请...${PLAIN}"
        fi
    fi

    echo -e "${YELLOW}正在申请 SSL 证书...${PLAIN}"
    mkdir -p $CERT_DIR
    
    if ! command -v ~/.acme.sh/acme.sh &> /dev/null; then
        curl https://get.acme.sh | sh
    fi
    
    ~/.acme.sh/acme.sh --upgrade --auto-upgrade
    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt

    # 将输入的 DOMAIN 转换为 acme.sh 所需的格式
    # 假设用户输入 "eddyemma.com kuawentrans.com"
    CERT_PARAMS=""
    for d in $DOMAIN; do
        CERT_PARAMS="$CERT_PARAMS -d $d"
    done

    # 申请证书 (Standalone模式，需要80端口)
    ~/.acme.sh/acme.sh --issue -d "$CERT_PARAMS" --standalone --keylength ec-256 --force

    if [ $? -ne 0 ]; then
        echo -e "${RED}证书申请失败！请检查域名解析是否正确，以及80端口是否开放。${PLAIN}"
        echo -e "${RED}如果 Nginx 正在运行，脚本会自动尝试停止它，但请确保没有其他程序占用 80 端口。${PLAIN}"
        exit 1
    fi

    # 获取用户输入域名列表中的第一个作为主域名
    MAIN_DOMAIN=$(echo $DOMAIN | awk '{print $1}')

    echo -e "${YELLOW}正在安装证书 (主域名: $MAIN_DOMAIN)...${PLAIN}"

    ~/.acme.sh/acme.sh --install-cert -d "$MAIN_DOMAIN" \
     --ecc \
     --fullchain-file $CERT_DIR/fullchain.crt \
     --key-file $CERT_DIR/private.key

    # 确保证书权限允许 Nginx 读取
    chmod 644 $CERT_DIR/fullchain.crt
    chmod 644 $CERT_DIR/private.key
    
    echo -e "${GREEN}证书申请并安装成功！${PLAIN}"
}

check_handshake_connectivity() {
    echo -e "${YELLOW}正在检查服务端与伪装域名 ($HANDSHAKE_SERVER) 的连通性...${PLAIN}"
    # 尝试连接伪装域名的 443 端口
    if curl -I --connect-timeout 5 https://$HANDSHAKE_SERVER >/dev/null 2>&1; then
        echo -e "${GREEN}连通性正常！ShadowTLS 可以正常工作。${PLAIN}"
    else
        echo -e "${RED}警告：服务器无法连接 $HANDSHAKE_SERVER。${PLAIN}"
        echo -e "${YELLOW}这可能导致 ShadowTLS 无法建立连接。建议检查 VPS 的 DNS 或网络设置。${PLAIN}"
        echo -e "尝试 Ping 测试:"
        ping -c 3 $HANDSHAKE_SERVER
    fi
}

config_singbox() {
    echo -e "${YELLOW}正在生成 Sing-box 配置...${PLAIN}"
    
    UUID=$(sing-box generate uuid)
    HY2_PASS=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9')
    STLS_PASS=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9')
    
    # 策略调整：
    # 1. VLESS (8443): 保持 Vision (高性能，主力)
    # 2. Hysteria2 (443 UDP): 保持
    # 3. ShadowTLS (9443): Detour 到 vless-internal
    # 4. vless-internal (10086): **移除 Vision**，改为标准 TLS。这是修复 ShadowTLS 不通的关键。
    cat > $SB_CONFIG <<EOF
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "::",
      "listen_port": 8443,
      "users": [
        {
          "uuid": "$UUID",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "$(echo $DOMAIN | awk '{print $1}')",
        "certificate_path": "$CERT_DIR/fullchain.crt",
        "key_path": "$CERT_DIR/private.key",
        "alpn": ["h3", "h2", "http/1.1"]
      }
    },
    {
      "type": "hysteria2",
      "tag": "hy2-in",
      "listen": "::",
      "listen_port": 443,
      "users": [
        {
          "password": "$HY2_PASS"
        }
      ],
      "tls": {
        "enabled": true,
        "certificate_path": "$CERT_DIR/fullchain.crt",
        "key_path": "$CERT_DIR/private.key",
        "alpn": ["h3"]
      }
    },
    {
      "type": "shadowtls",
      "tag": "stls-in",
      "listen": "::",
      "listen_port": 9443,
      "version": 3,
      "users": [
        {
          "password": "$STLS_PASS"
        }
      ],
      "handshake": {
        "server": "$HANDSHAKE_SERVER",
        "server_port": 443
      },
      "detour": "vless-internal"
    },
    {
      "type": "vless",
      "tag": "vless-internal",
      "listen": "127.0.0.1",
      "listen_port": 10086,
      "users": [
        {
          "uuid": "$UUID",
          "flow": "" 
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": ""$(echo $DOMAIN | awk '{print $1}'),
        "certificate_path": "$CERT_DIR/fullchain.crt",
        "key_path": "$CERT_DIR/private.key",
        "alpn": ["h3", "h2", "http/1.1"]
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ]
}
EOF
}

config_nginx() {
    echo -e "${YELLOW}正在配置 Nginx 伪装站 (开启 SSL)...${PLAIN}"
    rm -f /etc/nginx/sites-enabled/default

    # 关键修改：Nginx 现在监听 443 SSL，成为真正的主站
    cat > $NGINX_CONF <<EOF
server {
    listen 80;
    server_name $DOMAIN;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    server_name $DOMAIN;
    
    # SSL 配置
    ssl_certificate $CERT_DIR/fullchain.crt;
    ssl_certificate_key $CERT_DIR/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    
    root /var/www/html;
    index index.html;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF

    echo "<h1>Welcome to $DOMAIN</h1><p>Secure Blog Site (Nginx + Sing-box Coexistence)</p>" > /var/www/html/index.html
    
    systemctl restart nginx
}

configure_firewall() {
    echo -e "${YELLOW}正在配置系统防火墙 (UFW)...${PLAIN}"
    
    if ! command -v ufw &> /dev/null; then
        echo -e "${YELLOW}未检测到 UFW，跳过系统防火墙配置。${PLAIN}"
        return
    fi
    
    # 强制放行所有关键端口
    echo -e "放行端口: 80, 443 (TCP/UDP), 8443, 9443..."
    ufw allow 22/tcp
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw allow 443/udp
    ufw allow 8443/tcp
    ufw allow 9443/tcp
    
    ufw reload > /dev/null 2>&1
    echo -e "${GREEN}系统防火墙规则已更新！${PLAIN}"
}

update_singbox() {
    echo -e "${YELLOW}正在更新 Sing-box 内核...${PLAIN}"
    apt update
    apt install --only-upgrade sing-box
    systemctl restart sing-box
    echo -e "${GREEN}Sing-box 更新完成！${PLAIN}"
}

check_status() {
    echo -e "\n============================================"
    echo -e "         Sing-box 服务健康检查"
    echo -e "============================================"
    
    if systemctl is-active --quiet sing-box; then
        echo -e "Sing-box 状态: ${GREEN}运行中 (Active)${PLAIN}"
    else
        echo -e "Sing-box 状态: ${RED}未运行 (Inactive/Failed)${PLAIN}"
    fi
    
    echo -e "--------------------------------------------"
    echo -e "端口监听概览:"
    if command -v ss &> /dev/null; then
        ss -tulpn | grep -E "sing-box|nginx" | awk '{print "    - "$1" "$5" ("$7")"}'
    fi
    echo -e "============================================\n"
}

restart_service() {
    echo -e "${YELLOW}正在重启所有服务...${PLAIN}"
    systemctl restart sing-box
    systemctl restart nginx
    check_status
}

uninstall_all() {
    echo -e "${RED}警告：此操作将执行以下动作：${PLAIN}"
    echo -e "1. 停止并移除 sing-box 服务"
    echo -e "2. 删除 /etc/sing-box 配置文件及证书"
    echo -e "3. 删除 Nginx 的回落配置文件"
    echo -e "4. 重启 Nginx (恢复默认状态)"
    echo -e ""
    read -p "确认卸载吗？(y/n): " confirm
    if [[ "$confirm" != "y" ]]; then
        echo "取消卸载。"
        return
    fi

    echo -e "${YELLOW}开始卸载...${PLAIN}"
    systemctl stop sing-box
    systemctl disable sing-box
    if dpkg -l | grep -q sing-box; then
        apt remove -y sing-box
        apt purge -y sing-box
    fi
    rm -rf /etc/sing-box
    rm -f $NGINX_CONF
    rm -f /usr/local/bin/sing-box
    systemctl restart nginx
    echo -e "${GREEN}卸载完成！${PLAIN}"
}

generate_hiddify_json() {
    if [ ! -f $SB_CONFIG ]; then
        echo -e "${RED}配置文件不存在，请先安装！${PLAIN}"
        exit 1
    fi
    
    if ! command -v jq &> /dev/null; then
        apt install -y jq
    fi

    DOMAIN=$(jq -r '.inbounds[] | select(.type=="vless" and .listen_port==8443) | .tls.server_name' $SB_CONFIG)
    UUID=$(jq -r '.inbounds[] | select(.type=="vless" and .listen_port==8443) | .users[0].uuid' $SB_CONFIG)
    HY2_PASS=$(jq -r '.inbounds[] | select(.type=="hysteria2") | .users[0].password' $SB_CONFIG)
    STLS_PASS=$(jq -r '.inbounds[] | select(.type=="shadowtls") | .users[0].password' $SB_CONFIG)

    echo -e "\n${YELLOW}=== Hiddify / Sing-box 专用完整客户端配置 ===${PLAIN}"
    echo -e "${GREEN}说明: 全选下方 JSON 内容复制，在 Hiddify 中选择 'Import from Clipboard'${PLAIN}"
    echo -e "----------------------------------------------------"
    
    # 修改：ShadowTLS 内部去除 flow: vision，改为标准 TLS
    cat <<EOF
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "tag": "google",
        "address": "tls://8.8.8.8"
      },
      {
        "tag": "local",
        "address": "223.5.5.5",
        "detour": "direct"
      }
    ],
    "rules": [
      {
        "outbound": "any",
        "server": "local"
      },
      {
        "clash_mode": "Direct",
        "server": "local"
      },
      {
        "clash_mode": "Global",
        "server": "google"
      }
    ]
  },
  "outbounds": [
    {
      "type": "selector",
      "tag": "select",
      "outbounds": [
        "auto",
        "VLESS-Vision-8443",
        "Hysteria2-443",
        "ShadowTLS-Standard-9443"
      ],
      "default": "auto"
    },
    {
      "type": "urltest",
      "tag": "auto",
      "outbounds": [
        "VLESS-Vision-8443",
        "Hysteria2-443",
        "ShadowTLS-Standard-9443"
      ],
      "url": "http://cp.cloudflare.com/generate_204",
      "interval": "10m"
    },
    {
      "type": "vless",
      "tag": "VLESS-Vision-8443",
      "server": "${DOMAIN}",
      "server_port": 8443,
      "uuid": "${UUID}",
      "flow": "xtls-rprx-vision",
      "tls": {
        "enabled": true,
        "server_name": "${DOMAIN}",
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        }
      },
      "packet_encoding": "xudp"
    },
    {
      "type": "hysteria2",
      "tag": "Hysteria2-443",
      "server": "${DOMAIN}",
      "server_port": 443,
      "password": "${HY2_PASS}",
      "tls": {
        "enabled": true,
        "server_name": "${DOMAIN}",
        "alpn": [
          "h3"
        ]
      }
    },
    {
      "type": "shadowtls",
      "tag": "ShadowTLS-Layer",
      "server": "${DOMAIN}",
      "server_port": 9443,
      "version": 3,
      "password": "${STLS_PASS}",
      "tls": {
        "enabled": true,
        "server_name": "${HANDSHAKE_SERVER}",
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        }
      }
    },
    {
      "type": "vless",
      "tag": "ShadowTLS-Standard-9443",
      "detour": "ShadowTLS-Layer",
      "uuid": "${UUID}",
      "tls": {
        "enabled": true,
        "server_name": "${DOMAIN}",
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        }
      },
      "packet_encoding": "xudp"
    },
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "dns",
      "tag": "dns-out"
    }
  ],
  "route": {
    "rules": [
      {
        "protocol": "dns",
        "outbound": "dns-out"
      },
      {
        "clash_mode": "Direct",
        "outbound": "direct"
      },
      {
        "clash_mode": "Global",
        "outbound": "select"
      }
    ],
    "auto_detect_interface": true
  }
}
EOF
    echo -e "----------------------------------------------------"
    echo -e "${YELLOW}请复制上方所有内容 (包括大括号) 到 Hiddify 中导入。${PLAIN}\n"
}

show_qr() {
    if [ ! -f $SB_CONFIG ]; then
        echo -e "${RED}配置文件不存在，请先安装！${PLAIN}"
        exit 1
    fi
    
    if ! command -v qrencode &> /dev/null; then
        echo -e "${YELLOW}正在安装 qrencode...${PLAIN}"
        apt install -y qrencode
    fi
    
    if ! command -v jq &> /dev/null; then
        apt install -y jq
    fi

    DOMAIN=$(jq -r '.inbounds[] | select(.type=="vless" and .listen_port==8443) | .tls.server_name' $SB_CONFIG)
    UUID=$(jq -r '.inbounds[] | select(.type=="vless" and .listen_port==8443) | .users[0].uuid' $SB_CONFIG)
    HY2_PASS=$(jq -r '.inbounds[] | select(.type=="hysteria2") | .users[0].password' $SB_CONFIG)
    
    # 构建链接
    VLESS_LINK="vless://$UUID@$DOMAIN:8443?security=tls&encryption=none&alpn=h2,http/1.1&headerType=none&fp=chrome&type=tcp&flow=xtls-rprx-vision&sni=$DOMAIN#$DOMAIN-VLESS"
    HY2_LINK="hysteria2://$HY2_PASS@$DOMAIN:443?insecure=0&sni=$DOMAIN&mport=443-443#$DOMAIN-Hy2"

    echo -e "\n============================================"
    echo -e "              节点二维码分享"
    echo -e "============================================"
    
    echo -e "${YELLOW}1. VLESS + Vision + RealTLS (TCP 8443)${PLAIN}"
    echo -e "链接: $VLESS_LINK"
    echo -e ""
    qrencode -t ANSIUTF8 -k "$VLESS_LINK"
    echo -e ""

    echo -e "${YELLOW}2. Hysteria 2 (UDP 443)${PLAIN}"
    echo -e "链接: $HY2_LINK"
    echo -e ""
    qrencode -t ANSIUTF8 -k "$HY2_LINK"
    echo -e ""
    
    echo -e "${YELLOW}提示: ShadowTLS 配置较复杂，建议使用选项 7 生成完整 JSON 导入 Hiddify，或手动填写参数。${PLAIN}"
    echo -e "============================================\n"
}

show_info() {
    if [ ! -f $SB_CONFIG ]; then
        echo -e "${RED}配置文件不存在，请先安装！${PLAIN}"
        exit 1
    fi
    
    if ! command -v jq &> /dev/null; then
        apt install -y jq
    fi

    DOMAIN=$(jq -r '.inbounds[] | select(.type=="vless" and .listen_port==8443) | .tls.server_name' $SB_CONFIG)
    UUID=$(jq -r '.inbounds[] | select(.type=="vless" and .listen_port==8443) | .users[0].uuid' $SB_CONFIG)
    HY2_PASS=$(jq -r '.inbounds[] | select(.type=="hysteria2") | .users[0].password' $SB_CONFIG)
    STLS_PASS=$(jq -r '.inbounds[] | select(.type=="shadowtls") | .users[0].password' $SB_CONFIG)

    echo -e "\n=============================================="
    echo -e "       Sing-box 配置信息 (完美共存版)"
    echo -e "=============================================="
    echo -e "域名: ${GREEN}$DOMAIN${PLAIN}"
    echo -e "UUID: ${GREEN}$UUID${PLAIN}"
    echo -e "博客地址: ${GREEN}https://$DOMAIN${PLAIN} (Nginx TCP 443)"
    echo -e "----------------------------------------------"
    
    # 1. VLESS Reality (RealTLS) 链接 - 改为 8443
    VLESS_LINK="vless://$UUID@$DOMAIN:8443?security=tls&encryption=none&alpn=h2,http/1.1&headerType=none&fp=chrome&type=tcp&flow=xtls-rprx-vision&sni=$DOMAIN#$DOMAIN-VLESS-8443"
    echo -e "${YELLOW}[1] VLESS + Vision + RealTLS (TCP 8443)${PLAIN}"
    echo -e "链接: $VLESS_LINK"
    echo -e ""

    # 2. Hysteria 2 链接 - 依然是 443
    HY2_LINK="hysteria2://$HY2_PASS@$DOMAIN:443?insecure=0&sni=$DOMAIN&mport=443-443#$DOMAIN-Hy2"
    echo -e "${YELLOW}[2] Hysteria 2 (UDP 443) - 极速${PLAIN}"
    echo -e "密码: ${GREEN}$HY2_PASS${PLAIN}"
    echo -e "链接: $HY2_LINK"
    echo -e ""
    
    # 3. AnyTLS (ShadowTLS) 说明
    echo -e "${YELLOW}[3] ShadowTLS v3 (TCP 9443)${PLAIN}"
    echo -e "说明: 备用协议。ShadowTLS 外层已伪装，内层无需 Vision，使用标准 TLS 兼容性最好。"
    echo -e ""
    
    # 4. Clash Meta 配置输出
    echo -e "=============================================="
    echo -e "       Clash Meta (Mihomo) 配置片段"
    echo -e "=============================================="
    echo -e "${YELLOW}注意: 如果 Clash 连接失败，请检查日志。如果提示 'plugin not found'，请使用 Clash Verge Rev。${PLAIN}"
    # 修复：ShadowTLS 节点彻底移除 flow 字段，避免 Clash 报错或行为异常
    cat <<EOF
proxies:
  - name: "${DOMAIN}-VLESS"
    type: vless
    server: ${DOMAIN}
    port: 8443
    uuid: ${UUID}
    network: tcp
    tls: true
    udp: true
    flow: xtls-rprx-vision
    servername: ${DOMAIN}
    client-fingerprint: chrome

  - name: "${DOMAIN}-Hy2"
    type: hysteria2
    server: ${DOMAIN}
    port: 443
    password: ${HY2_PASS}
    sni: ${DOMAIN}
    skip-cert-verify: false
    alpn:
      - h3

  - name: "${DOMAIN}-ShadowTLS"
    type: vless
    server: ${DOMAIN}
    port: 9443
    uuid: ${UUID}
    network: tcp
    tls: true
    udp: true
    skip-cert-verify: true
    servername: ${DOMAIN}
    client-fingerprint: chrome
    plugin: shadow-tls
    plugin-opts:
      host: ${HANDSHAKE_SERVER}
      password: ${STLS_PASS}
      version: 3
EOF
    echo -e "==============================================\n"
}

main() {
    check_root
    echo -e "============================================"
    echo -e "Sing-box 一键管理脚本 v3.5 (优化 Windows Clash 兼容性)"
    echo -e "============================================"
    echo -e "1. 安装/重置 (Nginx@443 + Hy2@443 + VLESS@8443)"
    echo -e "2. 更新 Sing-box 内核"
    echo -e "3. 查看简易配置链接"
    echo -e "4. 彻底卸载 Sing-box"
    echo -e "5. 检查服务运行状态"
    echo -e "6. 重启所有服务"
    echo -e "7. 生成 Hiddify 专用完整配置 (JSON)"
    echo -e "8. 查看配置二维码"
    echo -e "0. 退出"
    echo -e "============================================"
    read -p "请选择 [0-8]: " choice

    case $choice in
        1)
            read -p "请输入你的域名,若有多个，用空格分隔 (例如 example.com example1.com): " DOMAIN
            install_dependencies
            configure_firewall
            install_singbox
            get_cert
            check_handshake_connectivity
            config_singbox
            #config_nginx
            systemctl restart sing-box
            show_info
            ;;
        2)
            update_singbox
            ;;
        3)
            show_info
            ;;
        4)
            uninstall_all
            ;;
        5)
            check_status
            ;;
        6)
            restart_service
            ;;
        7)
            generate_hiddify_json
            ;;
        8)
            show_qr
            ;;
        0)
            exit 0
            ;;
        *)
            echo -e "${RED}输入错误！${PLAIN}"
            ;;
    esac
}

main
