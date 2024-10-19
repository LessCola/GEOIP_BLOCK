#!/bin/bash

#####################################################
#This shell script is used for blocking ports based on GEOIP
#Usage：
#
#Author:Cola
#Web:https://mbe.cc
#Date:2024-09-05
#Version:1.0.0
#####################################################

plain='\033[0m'
red='\033[0;31m'
blue='\033[1;34m'
pink='\033[1;35m'
green='\033[0;32m'
yellow='\033[0;33m'

# 设置临时目录和国家简称
tempdir="/tmp"
country="cn"  # 根据需要设置为目标国家的简称
sourceURL="https://fastly.jsdelivr.net/gh/Loyalsoldier/geoip@release/text/"
ipFile="${country}.txt"
ipURL="${sourceURL}${ipFile}"
CHAIN_NAME="GEO_BLOCK"
SAVE_DIR=$(pwd)

IPSET_CONF="$SAVE_DIR/ipset.conf"
IPTABLES4_CONF="$SAVE_DIR/rules.v4"
IPTABLES6_CONF="$SAVE_DIR/rules.v6"


function checkPort() {

    local port=$1

    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        echo "Invalid port number."
        exit 1
    fi
}

function checkIp() {

    local ip=$1

    if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
        :
    elif [ "$ip" != "${1#*:[0-9a-fA-F]}" ]; then
        :
    else
        echo "Unrecognized IP format '$1'"\
        exit 1
    fi
}

function LOGE() {
    echo -e "${red}[ERR] $* ${plain}"
}

function LOGI() {
    echo -e "${green}[INF] $* ${plain}"
}

function LOGD() {
    echo -e "${yellow}[DEG] $* ${plain}"
}

chech_status(){

    if ! command -v bash &> /dev/null; then
        echo "bash is not installed. Please install it first."
        exit 1
    fi

    if ! command -v iptables &> /dev/null; then
        echo "iptables is not installed. Please install it first."
        exit 1
    fi

    if ! command -v ip6tables &> /dev/null; then
        echo "iptables is not installed. Please install it first."
        exit 1
    fi

    if ! command -v ipset &> /dev/null; then
        echo "ipset is not installed. Please install it first."
        exit 1
    fi

    INTERFACE=$(ip route | grep '^default' | awk '{print $5}')
    
    # # 检查是否获取到网卡名称
    # if [ -z "$INTERFACE" ]; then
    #     echo "无法检测到网卡名称，确保网络已配置并激活."
    #     exit 1
    # fi
    
    # echo "检测到的网卡名称: $INTERFACE"

    if iptables -L $CHAIN_NAME &>/dev/null; then
        :
    else
        # 创建链并添加到 INPUT 链
        echo "Creating chain $CHAIN_NAME and adding to INPUT."
        iptables -N $CHAIN_NAME
        iptables -I $CHAIN_NAME 1 -p tcp -s 0.0.0.0/0 --dport 22 -j ACCEPT
        iptables -A $CHAIN_NAME -j DROP
        iptables -A INPUT -j $CHAIN_NAME
    fi

    if ip6tables -L $CHAIN_NAME &>/dev/null; then
        :
    else
        # 创建链并添加到 INPUT 链
        echo "Creating chain $CHAIN_NAME and adding to INPUT."
        ip6tables -N $CHAIN_NAME
        ip6tables -A $CHAIN_NAME -j DROP
        ip6tables -A INPUT -j $CHAIN_NAME
    fi
    
}

show_menu() {

    clear

    echo -e "
GEO-IP-BLOCK 管理脚本
${green}0.${plain} 退出脚本
————————————————
${green}1.${plain} 查看规则
${green}2.${plain} 放行规则
${green}3.${plain} 封禁规则
${green}4.${plain} 删除规则
${green}5.${plain} 清空规则
"
    echo && read -e -p "请输入选择[0-3]:" num

    case "${num}" in
    0)
        exit 0
        ;;
    1)
        list_rules
        ;;
    2)
        allow
        ;;
    3)
        block
        ;;
    4)
        delete_rules
        ;;
    5)
        delete_all
        ;;
    *)
        LOGE "请输入正确的选项 [0-4]"
        ;;
    esac
}

list_rule(){

    printf "%-15s %-15s %-15s %-15s %-15s %-15s %-15s\n" "序号" "动作" "IP" "地区" "Version" "协议" "目标端口"

    # 获取并格式化 iptables 规则
    iptables_rules=$(iptables -L $CHAIN_NAME --line-numbers -n | awk 'NR > 2 {printf "%-13s %-13s %-15s %-13s %-13s %-13s\n", NR-2+offset, $2, $5, $7, $8, $10}')

    if [ -n "$iptables_rules" ]; then
        echo "$iptables_rules" | awk '
        {
            # 处理分割字段
            split($5, a, ":");
            split($6, b, "_");

            if ($3 == "0.0.0.0/0") {
                $3 = "ALL"
            }

            # 打印格式化输出
            printf "%-13s %-13s %-15s %-13s %-15s %-13s %-13s\n", $1, $2, $3, b[1], b[2], $4, a[2]
        }'

    else
        :
    fi

    # 计算 IPv4 规则数量
    ipv4_count=$(echo "$iptables_rules" | grep -v '^$' | wc -l)

    # echo $ipv4_count

    # 获取并格式化 ip6tables 规则
    ip6tables_rules=$(ip6tables -L $CHAIN_NAME --line-numbers -n | awk -v offset=$((ipv4_count)) 'NR > 2 {printf "%-13s %-13s %-15s %-13s %-13s %-13s\n", NR-2+offset, $2, $5, $7, $8, $10}')

    if [ -n "$ip6tables_rules" ]; then
        echo "$ip6tables_rules" | awk '
        {
            # 处理分割字段
            split($5, a, ":");
            split($6, b, "_");

            if ($3 == "::/0") {
                $3 = "ALL"
            }

            # 打印格式化输出
            printf "%-13s %-13s %-15s %-13s %-15s %-13s %-13s\n", $1, $2, $3, b[1], b[2], $4, a[2]
        }'

    else
        :
    fi

}

list_rules(){

    clear

    list_rule

    echo "按回车键返回菜单..."
    while true; do
        read -r -n 1 key
        if [ "$key" = "" ]; then
            show_menu
            break
        else
            :
        fi
    done

}

allow(){

    clear

    list_rule

    echo && read -e -p "请输入需要放行的IP地址:" ip

    checkIp "$ip"

    echo && read -e -p "请输入需要放行的端口:" port

    checkPort "$port"

    echo && read -e -p "请输入需要放行的协议 1.TCP 2.UDP 3.ALL:" tua

    if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then

        case $tua in
            1)
                iptables -I $CHAIN_NAME 1 -p tcp -s "$ip" --dport "$port" -j ACCEPT
                ;;
            2)
                iptables -I $CHAIN_NAME 1 -p udp -s "$ip" --dport "$port" -j ACCEPT
                ;;
            3)
                iptables -I $CHAIN_NAME 1 -p tcp -s "$ip" --dport "$port" -j ACCEPT
                iptables -I $CHAIN_NAME 1 -p udp -s "$ip" --dport "$port" -j ACCEPT
                ;;
        esac

    elif [ "$ip" != "${1#*:[0-9a-fA-F]}" ]; then

        case $tua in
            1)
                ip6tables -I $CHAIN_NAME 1 -p tcp -s $ip --dport $port -j ACCEPT
                ;;
            2)
                ip6tables -I $CHAIN_NAME 1 -p udp -s $ip --dport $port -j ACCEPT
                ;;
            3)
                ip6tables -I $CHAIN_NAME 1 -p tcp -s $ip --dport $port -j ACCEPT
                ip6tables -I $CHAIN_NAME 1 -p udp -s $ip --dport $port -j ACCEPT
                ;;
        esac


    else
        echo "add Fail"\
        exit 1
    fi

    clear 

    list_rule

    save

    echo && read -e -p "放行 $ip 的 $port 端口成功！是否继续放行？ 1.继续放行 0.回到主菜单" cont

    case "${cont}" in
    0)
        show_menu
        ;;
    1)
        allow
        ;;
    *)
        LOGE "请输入正确的选项 [0-1]"
        ;;
    esac

}

block() {

    clear

    list_rule
    
    echo && read -e -p "请选择封禁模式: 1.根据城市封禁 2.根据IP段封禁: " mode

    case "$mode" in
        1)
            echo && read -e -p "请输入需要封锁的地区: " country
            
            # 检查 ipset 集合是否已经存在
            if ipset list 2>/dev/null | grep "^Name: ${country}_4" && ipset list 2>/dev/null | grep "^Name: ${country}_6"; then
                echo "IP 地址集合 ${country}_4 和 ${country}_6 已存在，不需要重复下载。"
            else
                # 集合不存在，执行下载并创建集合
                rm $tempdir/$ipFile 2>/dev/null
                
                wget -P "$tempdir" "$ipURL" 1>/dev/null
                
                if [ $? -ne 0 ]; then
                    echo "Failed to download IP address list from ${ipURL}"
                    exit 1
                fi
                
                echo && read -e -p "请输入需要封锁的端口: " port
                
                if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
                    echo "Invalid port number."
                    exit 1
                fi
                
                echo && read -e -p "请输入需要封锁的协议 1.TCP 2.UDP 3.ALL: " tua
                
                # 创建 ipset 集合 ${country}_4
                if ! ipset list 2>/dev/null | grep "^Name: ${country}_4"; then
                    ipset create "${country}_4" hash:net 2>/dev/null
                fi

                # 读取文件并添加 IPv4 地址到 ipset 集合
                while IFS= read -r ip; do
                    if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
                        ipset add "${country}_4" "$ip" -exist
                    fi
                done < "$tempdir/$ipFile"
                
                # 创建 ipset 集合 ${country}_6
                if ! ipset list 2>/dev/null | grep "^Name: ${country}_6"; then
                    ipset create "${country}_6" hash:net family inet6 2>/dev/null
                fi

                # 读取文件并添加 IPv6 地址到 ipset 集合
                while IFS= read -r ip; do
                    if [[ $ip =~ ^[0-9a-fA-F:]+/[0-9]+$ ]]; then
                        ipset add "${country}_6" "$ip" -exist
                    fi
                done < "$tempdir/$ipFile"
                rm $tempdir/$ipFile
            fi

            case $tua in
                1)
                    iptables -A GEO_BLOCK -p tcp --dport $port -m set --match-set "${country}_4" src -j DROP      
                    ip6tables -A GEO_BLOCK -p tcp --dport $port -m set --match-set "${country}_6" src -j DROP    
                    ;;
                2)
                    iptables -A GEO_BLOCK -p udp --dport $port -m set --match-set "${country}_4" src -j DROP      
                    ip6tables -A GEO_BLOCK -p udp --dport $port -m set --match-set "${country}_6" src -j DROP     
                    ;;
                3)
                    iptables -A GEO_BLOCK -p tcp --dport $port -m set --match-set "${country}_4" src -j DROP      
                    ip6tables -A GEO_BLOCK -p tcp --dport $port -m set --match-set "${country}_6" src -j DROP  
                    iptables -A GEO_BLOCK -p udp --dport $port -m set --match-set "${country}_4" src -j DROP      
                    ip6tables -A GEO_BLOCK -p udp --dport $port -m set --match-set "${country}_6" src -j DROP 
                    ;;
            esac
            ;;
        
        2)
            # 输入 IP 段，如果未输入，默认 0.0.0.0/0
            echo && read -e -p "请输入需要封锁的IP段 (默认: 0.0.0.0/0): " ipRange
            ipRange=${ipRange:-0.0.0.0/0}  # 设置默认值为 0.0.0.0/0

            echo && read -e -p "请输入需要封锁的端口: " port

            if ! [[ "$port" =~ ^[0-9]+$ && "$port" -ge 1 && "$port" -le 65535 ]]; then
                echo "Invalid port number."
                exit 1
            fi
        
            echo && read -e -p "请输入需要封锁的协议 1.TCP 2.UDP 3.ALL: " tua
            
            if [[ $ipRange =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
                case $tua in
                    1)
                        iptables -I $CHAIN_NAME 1 -p tcp -s "$ipRange" --dport "$port" -j DROP
                        ;;
                    2)
                        iptables -I $CHAIN_NAME 1 -p udp -s "$ipRange" --dport "$port" -j DROP
                        ;;
                    3)
                        iptables -I $CHAIN_NAME 1 -p tcp -s "$ipRange" --dport "$port" -j DROP
                        iptables -I $CHAIN_NAME 1 -p udp -s "$ipRange" --dport "$port" -j DROP
                        ;;
                esac
            elif [[ $ipRange =~ ^[0-9a-fA-F:]+/[0-9]+$ ]]; then
                case $tua in
                    1)
                        ip6tables -I $CHAIN_NAME 1 -p tcp -s "$ipRange" --dport "$port" -j DROP
                        ;;
                    2)
                        ip6tables -I $CHAIN_NAME 1 -p udp -s "$ipRange" --dport "$port" -j DROP
                        ;;
                    3)
                        ip6tables -I $CHAIN_NAME 1 -p tcp -s "$ipRange" --dport "$port" -j DROP
                        ip6tables -I $CHAIN_NAME 1 -p udp -s "$ipRange" --dport "$port" -j DROP
                        ;;
                esac
            else
                echo "Invalid IP range format."
                exit 1
            fi
            ;;
        *)
            echo "无效的选项，请选择 1 或 2."
            exit 1
            ;;
    esac

    clear

    list_rule

    save

    echo && read -e -p "封禁操作成功！是否继续封禁？ 1.继续封禁 2.回到主菜单: " cont

    case "${cont}" in
        1)
            block
            ;;
        2)
            show_menu
            ;;
        *)
            LOGE "请输入正确的选项 [1-2]"
            ;;
    esac
}

delete_rules() {

    clear

    printf "%-15s %-15s %-15s %-15s %-15s %-15s %-15s\n" "序号" "动作" "IP" "地区" "Version" "协议" "目标端口"

    # 获取并格式化 iptables 规则
    iptables_rules=$(iptables -L $CHAIN_NAME --line-numbers -n | awk 'NR > 2 {printf "%-13s %-13s %-15s %-13s %-13s %-13s\n", NR-2+offset, $2, $5, $7, $8, $10}')

    if [ -n "$iptables_rules" ]; then
        echo "$iptables_rules" | awk '
        {
            # 处理分割字段
            split($5, a, ":");
            split($6, b, "_");

            if ($3 == "0.0.0.0/0") {
                $3 = "ALL"
            }

            # 打印格式化输出
            printf "%-13s %-13s %-15s %-13s %-15s %-13s %-13s\n", $1, $2, $3, b[1], b[2], $4, a[2]
        }'

    else
        :
    fi

    # 计算 IPv4 规则数量
    ipv4_count=$(echo "$iptables_rules" | grep -v '^$' | wc -l)

    # echo $ipv4_count

    # 获取并格式化 ip6tables 规则
    ip6tables_rules=$(ip6tables -L $CHAIN_NAME --line-numbers -n | awk -v offset=$((ipv4_count)) 'NR > 2 {printf "%-13s %-13s %-15s %-13s %-13s %-13s\n", NR-2+offset, $2, $5, $7, $8, $10}')

    if [ -n "$ip6tables_rules" ]; then
        echo "$ip6tables_rules" | awk '
        {
            # 处理分割字段
            split($5, a, ":");
            split($6, b, "_");

            if ($3 == "::/0") {
                $3 = "ALL"
            }

            # 打印格式化输出
            printf "%-13s %-13s %-15s %-13s %-15s %-13s %-13s\n", $1, $2, $3, b[1], b[2], $4, a[2]
        }'

    else
        :
    fi

    # 计算总规则数
    ipv6_count=$(echo "$ip6tables_rules" | wc -l)
    all_count=$((ipv4_count + ipv6_count))

    # 提示用户选择要删除的规则
    read -e -p "请输入要删除的规则序号，或者按0回到主菜单：" rule_number

    if [ "$rule_number" -eq 0 ]; then

        show_menu

    elif [ "$rule_number" -ge 1 ] && [ "$rule_number" -le "$all_count" ]; then

        if [ "$rule_number" -le "$ipv4_count" ]; then
            echo "删除 IPv4 链 $CHAIN_NAME 上的序号 $rule_number 的规则"
            iptables -D $CHAIN_NAME $rule_number
        elif [ "$rule_number" -le "$((ipv4_count + ipv6_count))" ]; then
            ipv6_number=$((rule_number - ipv4_count))
            echo "删除 IPv6 链 $CHAIN_NAME 上的序号 $ipv6_number 的规则"
            ip6tables -D $CHAIN_NAME $ipv6_number
        else
            echo "无效的规则序号 '$rule_number'"
            exit 1
        fi

    else

        echo "请输入正确的选项 [1-$all_count]"

    fi

    save

    delete_rules
}

delete_all(){

    if iptables -L $CHAIN_NAME &>/dev/null; then
        iptables -F $CHAIN_NAME &>/dev/null
    else
        :
    fi

    if ip6tables -L $CHAIN_NAME &>/dev/null; then
        ip6tables -F $CHAIN_NAME &>/dev/null
    else
        :
    fi

    ipset list | awk '/^Name:/ {print $2}' | xargs -I {} ipset destroy {}

    [ -f "$IPSET_CONF" ] && rm "$IPSET_CONF" 2>/dev/null

    [ -f "$IPTABLES4_CONF" ] && rm "$IPTABLES4_CONF" 2>/dev/null

    [ -f "$IPTABLES6_CONF" ] && rm "$IPTABLES6_CONF" 2>/dev/null

    echo '删除所有规则成功'

    show_menu

}

save(){

    [ -f "$IPSET_CONF" ] && rm "$IPSET_CONF"

    [ -f "$IPTABLES4_CONF" ] && rm "$IPTABLES4_CONF"

    [ -f "$IPTABLES6_CONF" ] && rm "$IPTABLES6_CONF"

    ipset save > $IPSET_CONF
    iptables-save > $IPTABLES4_CONF
    ip6tables-save > $IPTABLES6_CONF

}

restore() {

    if [ -f "$IPSET_CONF" ]; then
        ipset restore < "$IPSET_CONF" || echo "Failed to restore ipset configuration."
    else
        echo "No ipset configuration file found."
    fi

    if [ -f "$IPTABLES4_CONF" ]; then
        iptables-restore < "$IPTABLES4_CONF" || echo "Failed to restore IPv4 iptables configuration."
    else
        echo "No IPv4 iptables configuration file found."
    fi

    if [ -f "$IPTABLES6_CONF" ]; then
        ip6tables-restore < "$IPTABLES6_CONF" || echo "Failed to restore IPv6 iptables configuration."
    else
        echo "No IPv6 iptables configuration file found."
    fi
}

if [ "$1" = "restore" ]; then
    restore
else
    chech_status
    show_menu
fi

# chech_status
# show_menu
