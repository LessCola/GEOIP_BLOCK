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

    if ! command -v iptables &> /dev/null; then
        echo "iptables is not installed. Please install it first."
        exit 1
    fi

    if ! command -v ipset &> /dev/null; then
        echo "ipset is not installed. Please install it first."
        exit 1
    fi

    if iptables -L $CHAIN_NAME &>/dev/null; then
        :
    else
        # 创建链并添加到 INPUT 链
        echo "Creating chain $CHAIN_NAME and adding to INPUT."
        iptables -N $CHAIN_NAME
        iptables -A INPUT -j $CHAIN_NAME
    fi

    if ip6tables -L $CHAIN_NAME &>/dev/null; then
        :
    else
        # 创建链并添加到 INPUT 链
        echo "Creating chain $CHAIN_NAME and adding to INPUT."
        ip6tables -N $CHAIN_NAME
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
${green}2.${plain} 新增规则
${green}3.${plain} 删除规则
${green}4.${plain} 清空规则
"
    echo && read -p "请输入选择[0-3]:" num

    case "${num}" in
    0)
        exit 0
        ;;
    1)
        list_rules
        ;;
    2)
        add_rules
        ;;
    3)
        delete_rules
        ;;
    4)
        delete_all
        ;;
    *)
        LOGE "请输入正确的选项 [0-4]"
        ;;
    esac
}

list_rule(){

    printf "%-15s %-15s %-15s %-15s %-15s %-15s\n" "序号" "动作" "IP" "地区" "协议" "目标端口"

    # 获取并格式化 iptables 规则
    iptables_rules=$(sudo iptables -L $CHAIN_NAME --line-numbers -n | awk 'NR > 2 {printf "%-13s %-13s %-13s %-13s %-13s %-13s\n", NR-2, $2, $5, $7, $8, $10}')
    if [ -n "$iptables_rules" ]; then

        echo "$iptables_rules" | awk '
        {
            # 处理分割字段
            split($5, a, ":");
            split($6, b, "_");
            
            if (a[2] == "") {
                a[2] = "None"
            }

            if (b[1] == "") {
                b[1] = "None"
            }else{
                $3 = "None"
            }

            # 打印格式化输出
            printf "%-13s %-13s %-15s %-13s %-13s %-13s\n", $1, $2, $3, b[1], $4, a[2]
        }'

    else
        :
    fi

    # 计算 IPv4 规则数量
    ipv4_count=$(echo "$iptables_rules" | grep -v '^$' | wc -l)

    # echo $ipv4_count

    # 获取并格式化 ip6tables 规则
    ip6tables_rules=$(sudo ip6tables -L $CHAIN_NAME --line-numbers -n | awk -v offset=$((ipv4_count)) 'NR > 2 {printf "%-13s %-13s %-15s %-13s %-13s %-13s\n", NR-2+offset, $2, $5, $7, $8, $10}')

    if [ -n "$ip6tables_rules" ]; then

        echo "$ip6tables_rules" | awk '
        {
            # 处理分割字段
            split($5, a, ":");
            split($6, b, "_");
            
            if (a[2] == "") {
                a[2] = "None"
            }

            if (b[1] == "") {
                b[1] = "None"
            }else{
                $3 = "None"
            }

            # 打印格式化输出
            printf "%-13s %-13s %-15s %-13s %-13s %-13s\n", $1, $2, $3, b[1], $4, a[2]
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

add_rules(){
    clear
    echo -e "
${green}1.${plain} 放行IP
${green}2.${plain} 封禁端口
${green}0.${plain} 回到菜单
"
    echo && read -p "请输入选择[0-2]:" num
    case "${num}" in
    0)
        show_menu
        ;;
    1)
        allow
        ;;
    2)
        block
        ;;
    *)
        LOGE "请输入正确的选项 [0-2]"
        ;;
    esac

}

allow(){

    clear

    list_rule

    echo && read -p "请输入需要放行的IP地址:"

    checkIp "$ip"

    echo && read -p "请输入需要放行的端口:" port

    checkPort "$port"

    echo && read -p "请输入需要放行的协议 1.TCP 2.UDP 3.ALL:" tua

    if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then

        case $tua in
            1)
                iptables -I $CHAIN_NAME 1 -i eth0 -p tcp -s "$ip" --dport "$port" -j ACCEPT
                ;;
            2)
                iptables -I $CHAIN_NAME 1 -i eth0 -p udp -s "$ip" --dport "$port" -j ACCEPT
                ;;
            3)
                iptables -I $CHAIN_NAME 1 -i eth0 -p tcp -s "$ip" --dport "$port" -j ACCEPT
                iptables -I $CHAIN_NAME 1 -i eth0 -p udp -s "$ip" --dport "$port" -j ACCEPT
                ;;
        esac

    elif [ "$ip" != "${1#*:[0-9a-fA-F]}" ]; then

        case $tua in
            1)
                ip6tables -I $CHAIN_NAME 1 -i eth0 -p tcp -s $ip --dport $port -j ACCEPT
                ;;
            2)
                ip6tables -I $CHAIN_NAME 1 -i eth0 -p udp -s $ip --dport $port -j ACCEPT
                ;;
            3)
                ip6tables -I $CHAIN_NAME 1 -i eth0 -p tcp -s $ip --dport $port -j ACCEPT
                ip6tables -I $CHAIN_NAME 1 -i eth0 -p udp -s $ip --dport $port -j ACCEPT
                ;;
        esac


    else
        echo "add Fail"\
        exit 1
    fi

    clear 

    list_rule

    echo && read -p "放行 $ip 的 $port 端口成功！是否继续放行？ 1.继续放行 0.回到主菜单" cont

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

block(){

    clear

    list_rule

    echo && read -p "请输入需要封锁的地区:" country

    rm $tempdir/$ipFile

    wget -P "$tempdir" "$ipURL"

    if [ $? -ne 0 ]; then
        echo "Failed to download IP address list from ${ipURL}"
        exit 1
    fi

    echo && read -p "请输入需要封锁的端口:" port

    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        echo "Invalid port number."
        exit 1
    fi

    echo && read -p "请输入需要封锁的协议 1.TCP 2.UDP 3.ALL:" tua

    # 销毁现有的 ipset 集合
    ipset destroy "${country}_4" 2>/dev/null
    ipset destroy "${country}_6" 2>/dev/null

    # 创建新的 ipset 集合
    ipset create "${country}_4" hash:net 2>/dev/null
    ipset create "${country}_6" hash:net family inet6 2>/dev/null

    # 读取文件并添加 IP 地址到 ipset 集合
    while IFS= read -r ip; do
        if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
            ipset add "${country}_4" "$ip" -exist
        elif [[ $ip =~ ^[0-9a-fA-F:]+/[0-9]+$ ]]; then
            ipset add "${country}_6" "$ip" -exist
        else
            echo "$ip is not a valid IP address range."
        fi
    done < "$tempdir/$ipFile"

        rm $tempdir/$ipFile

    case $tua in
        1)
            iptables -A GEO_BLOCK -i eth0 -p tcp --dport $port -m set --match-set "${country}_4" src -j DROP      
            ip6tables -A GEO_BLOCK -i eth0 -p tcp --dport $port -m set --match-set "${country}_6" src -j DROP    
            ;;
        2)
            iptables -A GEO_BLOCK -i eth0 -p udp --dport $port -m set --match-set "${country}_4" src -j DROP      
            ip6tables -A GEO_BLOCK -i eth0 -p udp --dport $port -m set --match-set "${country}_6" src -j DROP     
            ;;
        3)
            iptables -A GEO_BLOCK -i eth0 -p tcp --dport $port -m set --match-set "${country}_4" src -j DROP      
            ip6tables -A GEO_BLOCK -i eth0 -p tcp --dport $port -m set --match-set "${country}_6" src -j DROP  
            iptables -A GEO_BLOCK -i eth0 -p udp --dport $port -m set --match-set "${country}_4" src -j DROP      
            ip6tables -A GEO_BLOCK -i eth0 -p udp --dport $port -m set --match-set "${country}_6" src -j DROP 
            ;;
    esac

    clear

    list_rule

    echo && read -p "封禁 $country 的 $port 端口成功！是否继续封禁？ 1.继续封禁 2.回到主菜单" cont

    case "${cont}" in
    1)
        allow
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

    printf "%-15s %-15s %-15s %-15s %-15s %-15s\n" "序号" "动作" "IP" "地区" "协议" "目标端口"

    # 获取并格式化 iptables 规则
    iptables_rules=$(sudo iptables -L $CHAIN_NAME --line-numbers -n | awk 'NR > 2 {printf "%-13s %-13s %-13s %-13s %-13s %-13s\n", NR-2, $2, $5, $7, $8, $10}')
    if [ -n "$iptables_rules" ]; then

        echo "$iptables_rules" | awk '
        {
            # 处理分割字段
            split($5, a, ":");
            split($6, b, "_");
            
            if (a[2] == "") {
                a[2] = "None"
            }

            if (b[1] == "") {
                b[1] = "None"
            }else{
                $3 = "None"
            }

            # 打印格式化输出
            printf "%-13s %-13s %-15s %-13s %-13s %-13s\n", $1, $2, $3, b[1], $4, a[2]
        }'

    else
        :
    fi

    # 计算 IPv4 规则数量
    ipv4_count=$(echo "$iptables_rules" | grep -v '^$' | wc -l)

    # echo $ipv4_count

    # 获取并格式化 ip6tables 规则
    ip6tables_rules=$(sudo ip6tables -L $CHAIN_NAME --line-numbers -n | awk -v offset=$((ipv4_count)) 'NR > 2 {printf "%-13s %-13s %-15s %-13s %-13s %-13s\n", NR-2+offset, $2, $5, $7, $8, $10}')

    if [ -n "$ip6tables_rules" ]; then

        echo "$ip6tables_rules" | awk '
        {
            # 处理分割字段
            split($5, a, ":");
            split($6, b, "_");
            
            if (a[2] == "") {
                a[2] = "None"
            }

            if (b[1] == "") {
                b[1] = "None"
            }else{
                $3 = "None"
            }

            # 打印格式化输出
            printf "%-13s %-13s %-15s %-13s %-13s %-13s\n", $1, $2, $3, b[1], $4, a[2]
        }'

    else
        :
    fi

    # 计算总规则数
    ipv6_count=$(echo "$ip6tables_rules" | wc -l)
    all_count=$((ipv4_count + ipv6_count))

    # 提示用户选择要删除的规则
    read -p "请输入要删除的规则序号，或者按0回到主菜单：" rule_number

    if [ "$rule_number" -eq 0 ]; then

        show_menu

    elif [ "$rule_number" -ge 1 ] && [ "$rule_number" -le "$all_count" ]; then

        if [ "$rule_number" -le "$ipv4_count" ]; then
            echo "删除 IPv4 链 $CHAIN_NAME 上的序号 $rule_number 的规则"
            sudo iptables -D $CHAIN_NAME $rule_number
        elif [ "$rule_number" -le "$((ipv4_count + ipv6_count))" ]; then
            ipv6_number=$((rule_number - ipv4_count))
            echo "删除 IPv6 链 $CHAIN_NAME 上的序号 $ipv6_number 的规则"
            sudo ip6tables -D $CHAIN_NAME $ipv6_number
        else
            echo "无效的规则序号 '$rule_number'"
            exit 1
        fi

    else

        echo "请输入正确的选项 [1-$all_count]"

    fi

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

    echo '删除所有规则成功'

}


chech_status
show_menu
