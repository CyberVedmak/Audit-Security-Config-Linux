#!/bin/sh

#################################################################################
#
# Audit Security Config Linux / Скрипт аудита параметров безопасности ОС Linux
# © CyberVedmak, 2025
# 
# https://github.com/CyberVedmak
# https://gitverse.ru/CyberVedmak
# ------------------
#
# v1.0 beta from 16.05.2025
#
#################################################################################
#
# VERIFICATION STATUS: ALERT, WARNING, OK
# VERIFICATION RATINGS: CRITICAL, HIGH, MIDDLE
#
#################################################################################

LOG_FILE="audit_config_linux.log"
VERSION="v1.0  beta from 16.05.2025"
CURRENT_DATE=$(date +"%Y-%m-%d %H:%M:%S")
HOSTNAME=$(hostname)
IP_ADDRESS=$(hostname -I | awk '{print $1}')

echo -n > $LOG_FILE

####
echo "########################################" >> $LOG_FILE
echo "" >> $LOG_FILE
echo "Audit Security Config Linux /  Скрипт аудита параметров безопасности ОС Linux" >> $LOG_FILE
echo "© CyberVedmak, 2025" >> $LOG_FILE
echo "" >> $LOG_FILE
echo "https://github.com/CyberVedmak" >> $LOG_FILE
echo "https://gitverse.ru/CyberVedmak" >> $LOG_FILE
echo "" >> $LOG_FILE
echo "$VERSION" >> $LOG_FILE
echo "" >> $LOG_FILE
echo "$CURRENT_DATE" >> $LOG_FILE
echo "" >> $LOG_FILE
echo "#########################################" >> $LOG_FILE
echo "" >> $LOG_FILE
echo "Имя хоста: $HOSTNAME" >> $LOG_FILE
echo "Имя хоста: $IP_ADDRESS" >> $LOG_FILE
echo "" >> $LOG_FILE
echo "" >> $LOG_FILE
echo "" >> $LOG_FILE
####


###### 1
# 1.1 kernel.randomize_va_space = 2
expected_value="2"
current_value=$(grep 'kernel\.randomize_va_space' /etc/sysctl.conf | awk '{print $NF}')
if [[ "$current_value" != "" ]]; then
    if [[ "$current_value" == "$expected_value" ]]; then
        # Значение совпадает с эталон
        printf "%-55s %-20s\n" "Status kernel.randomize_va_space:" "OK" >> $LOG_FILE
    else
        # Значение отличается от эталона!
        printf "%-55s %-20s\n" "Status kernel.randomize_va_space:" "ALERT   [ HIGH ]" >> $LOG_FILE
    fi
else
        # Искомый параметр отсутствует
        printf "%-55s %-20s\n" "Status kernel.randomize_va_space:" "WARNING" >> $LOG_FILE
fi



# 1.2 fs.protected_symlinks = 1
expected_value="1"
current_value=$(grep 'fs\.protected_symlinks' /etc/sysctl.conf | awk '{print $NF}')
if [[ "$current_value" != "" ]]; then
    if [[ "$current_value" == "$expected_value" ]]; then
        # Значение совпадает с эталоном
	 printf "%-55s %-20s\n" "Status fs.protected_symlinks:" "OK" >> $LOG_FILE
    else
        # Значение отличается от эталона!
         printf "%-55s %-20s\n" "Status fs.protected_symlinks:" "ALERT   [ HIGH ]" >> $LOG_FILE
    fi
else
        # Искомый параметр отсутствует
         printf "%-55s %-20s\n" "Status fs.protected_symlinks:" "WARNING" >> $LOG_FILE
fi



# 1.3 fs.protected_fifos = 2
expected_value="2"
current_value=$(grep 'fs\.protected_fifos' /etc/sysctl.conf | awk '{print $NF}')
if [[ "$current_value" != "" ]]; then
    if [[ "$current_value" == "$expected_value" ]]; then
        # Значение совпадает с эталоном
        printf "%-55s %-20s\n" "Status fs.protected_fifos:" "OK" >> $LOG_FILE
    else
        # Значение отличается от эталона!
        printf "%-55s %-20s\n" "Status fs.protected_fifos:" "ALERT   [ HIGH ]" >> $LOG_FILE
    fi
else
        # Искомый параметр отсутствует
        printf "%-55s %-20s\n" "Status fs.protected_fifos:" "WARNING" >> $LOG_FILE
fi



# 1.4 fs.protected_regular = 2
expected_value="2"
current_value=$(grep 'fs\.protected_regular' /etc/sysctl.conf | awk '{print $NF}')
if [[ "$current_value" != "" ]]; then
    if [[ "$current_value" == "$expected_value" ]]; then
        # Значение совпадает с эталоном
        printf "%-55s %-20s\n" "Status fs.protected_fifos:" "OK" >> $LOG_FILE
    else
        # Значение отличается от эталона!
        printf "%-55s %-20s\n" "Status fs.protected_fifos:" "ALERT   [ HIGH ]" >> $LOG_FILE
    fi
else
        # Искомый параметр отсутствует
        printf "%-55s %-20s\n" "Status fs.protected_fifos:" "WARNING" >> $LOG_FILE
fi



# 1.5 fs.suid_dumpable = 0
expected_value="0"
current_value=$(grep 'fs\.suid_dumpable' /etc/sysctl.conf | awk '{print $NF}')
if [[ "$current_value" != "" ]]; then
    if [[ "$current_value" == "$expected_value" ]]; then
        # Значение совпадает с эталоном
        printf "%-55s %-20s\n" "Status fs.suid_dumpable:" "OK" >> $LOG_FILE
    else
        # Значение отличается от эталона!
        printf "%-55s %-20s\n" "Status fs.suid_dumpable:" "ALERT   [ HIGH ]" >> $LOG_FILE
    fi
else
        # Искомый параметр отсутствует
        printf "%-55s %-20s\n" "Status fs.suid_dumpable:" "WARNING" >> $LOG_FILE
fi



# 1.6 kernel.dmesg_restrict = 1
expected_value="1"
current_value=$(grep 'kernel\.dmesg_restrict' /etc/sysctl.conf | awk '{print $NF}')
if [[ "$current_value" != "" ]]; then
    if [[ "$current_value" == "$expected_value" ]]; then
        # Значение совпадает с эталоном
        printf "%-55s %-20s\n" "Status kernel.dmesg_restrict:" "OK" >> $LOG_FILE
    else
        # Значение отличается от эталона!
        printf "%-55s %-20s\n" "Status kernel.dmesg_restrict:" "ALERT   [ HIGH ]" >> $LOG_FILE
    fi
else
        # Искомый параметр отсутствует
        printf "%-55s %-20s\n" "Status kernel.dmesg_restrict:" "WARNING" >> $LOG_FILE
fi



# 1.7 net.ipv6.conf.all.disable_ipv6 = 1
expected_value="1"
current_value=$(grep 'net\.ipv6\.conf\.all\.disable_ipv6' /etc/sysctl.conf | awk '{print $NF}')
if [[ "$current_value" != "" ]]; then
    if [[ "$current_value" == "$expected_value" ]]; then
        # Значение совпадает с эталоном
        printf "%-55s %-20s\n" "Status net.ipv6.conf.all.disable_ipv6:" "OK" >> $LOG_FILE
    else
        # Значение отличается от эталона!
        printf "%-55s %-20s\n" "Status net.ipv6.conf.all.disable_ipv6:" "ALERT   [ MIDDLE ]" >> $LOG_FILE
    fi
else
        # Искомый параметр отсутствует
        printf "%-55s %-20s\n" "Status net.ipv6.conf.all.disable_ipv6:" "WARNING" >> $LOG_FILE
fi



# 1.8 net.ipv4.conf.default.rp_filter = 1
expected_value="1"
current_value=$(grep 'net\.ipv4\.conf\.default.rp_filter' /etc/sysctl.conf | awk '{print $NF}')
if [[ "$current_value" != "" ]]; then
    if [[ "$current_value" == "$expected_value" ]]; then
        # Значение совпадает с эталоном
        printf "%-55s %-20s\n" "Status net.ipv4.conf.default.rp_filter:" "OK" >> $LOG_FILE
    else
        # Значение отличается от эталона!
        printf "%-55s %-20s\n" "Status net.ipv4.conf.default.rp_filter:" "ALERT   [ HIGH ]" >> $LOG_FILE
    fi
else
        # Искомый параметр отсутствует
        printf "%-55s %-20s\n" "Status net.ipv4.conf.default.rp_filter:" "WARNING" >> $LOG_FILE
fi



# 1.9 kernel.yama.ptrace_scope = 3
expected_value="3"
current_value=$(grep 'kernel\.yama\.ptrace_scope' /etc/sysctl.conf | awk '{print $NF}')
if [[ "$current_value" != "" ]]; then
    if [[ "$current_value" == "$expected_value" ]]; then
        # Значение совпадает с эталоном
        printf "%-55s %-20s\n" "Status kernel.yama.ptrace_scope:" "OK" >> $LOG_FILE
    else
        # Значение отличается от эталона!
        printf "%-55s %-20s\n" "Status kernel.yama.ptrace_scope:" "ALERT   [ HIGH ]" >> $LOG_FILE
    fi
else
        # Искомый параметр отсутствует
        printf "%-55s %-20s\n" "Status kernel.yama.ptrace_scope:" "WARNING" >> $LOG_FILE
fi



# 1.10 net.ipv4.icmp_echo_ignore_broadcasts = 1
expected_value="1"
current_value=$(grep 'net\.ipv4\.icmp_echo_ignore_broadcasts' /etc/sysctl.conf | awk '{print $NF}')
if [[ "$current_value" != "" ]]; then
    if [[ "$current_value" == "$expected_value" ]]; then
        # Значение совпадает с эталоном
        printf "%-55s %-20s\n" "Status net.ipv4.icmp_echo_ignore_broadcasts:" "OK" >> $LOG_FILE
    else
        # Значение отличается от эталона!
        printf "%-55s %-20s\n" "Status net.ipv4.icmp_echo_ignore_broadcasts:" "ALERT   [ MIDDLE ]" >> $LOG_FILE
    fi
else
        # Искомый параметр отсутствует
	printf "%-55s %-20s\n" "Status net.ipv4.icmp_echo_ignore_broadcasts:" "WARNING" >> $LOG_FILE
fi


echo "" >> $LOG_FILE
echo "" >> $LOG_FILE


###### 2
# 2.1 check /etc/passwd - 644
file="/etc/passwd"
expected_permissions="644"
current_permissions=$(stat -c '%a' "$file")
if [ "$current_permissions" = "$expected_permissions" ]; then
	printf "%-55s %-20s\n" "Status check /etc/passwd:" "OK" >> $LOG_FILE
else
        printf "%-55s %-20s\n" "Status check /etc/passwd:" "ALERT   [ CRITICAL ]" >> $LOG_FILE
fi



# 2.2 check /etc/group - 644
file="/etc/group"
expected_permissions="644"
current_permissions=$(stat -c '%a' "$file")
if [ "$current_permissions" = "$expected_permissions" ]; then
        printf "%-55s %-20s\n" "Status check /etc/group:" "OK" >> $LOG_FILE
else
        printf "%-55s %-20s\n" "Status check /etc/group:" "ALERT   [ CRITICAL ]" >> $LOG_FILE
fi



# 2.3 check /etc/shadow - 000
file="/etc/shadow"
expected_permissions="0"
current_permissions=$(stat -c '%a' "$file")
if [ "$current_permissions" = "$expected_permissions" ]; then
        printf "%-55s %-20s\n" "Status check /etc/shadow:" "OK" >> $LOG_FILE
else
        printf "%-55s %-20s\n" "Status check /etc/shadow:" "ALERT   [ CRITICAL ]" >> $LOG_FILE
fi



# 2.4 check /var/log/messages - 600
file="/var/log/messages"
expected_permissions="600"
current_permissions=$(stat -c '%a' "$file")
if [ "$current_permissions" = "$expected_permissions" ]; then
        printf "%-55s %-20s\n" "Status check /var/log/messages:" "OK" >> $LOG_FILE
else
        printf "%-55s %-20s\n" "Status check /var/log/messages:" "ALERT   [ MIDDLE ]" >> $LOG_FILE
fi



# 2.5 check /home/* - 740
output_file_25="${LOG_FILE}.2.5"
dir="/home/*"
expected_permissions="740"
echo -n > $output_file_25
for folder in $dir; do
    if [ -d "$folder" ]; then
        current_permissions=$(stat -c '%a' "$folder")
        if [ "$current_permissions" != "$expected_permissions" ]; then
            echo "Каталог $folder отличается от ожидаемых прав ($expected_permissions). Текущие права: $current_permissions" >> $output_file_25
            errors="$errors\nОшибка! Каталог $folder отличается от ожидаемых прав ($expected_permissions). Текущие права: $current_permissions"
        fi
    fi
done
if [ -z "$errors" ]; then
    printf "%-55s %-20s\n" "Status check /home/*:" "OK" >> $LOG_FILE
else
    printf "%-55s %-20s\n" "Status check /home/*:" "ALERT   [ HIGH ]                     see $output_file_25" >> $LOG_FILE
fi



# 2.6 check /etc/cron* - 700
output_file_26="${LOG_FILE}.2.6"
dir="/etc/cron*"
expected_permissions="700"
echo -n > $output_file_26
for folder in $dir; do
    if [ -d "$folder" ]; then
        current_permissions=$(stat -c '%a' "$folder")
        if [ "$current_permissions" != "$expected_permissions" ]; then
            echo "Каталог $folder отличается от ожидаемых прав ($expected_permissions). Текущие права: $current_permissions" >> $output_file_26
            errors="$errors\nКаталог $folder отличается от ожидаемых прав ($expected_permissions). Текущие права: $current_permissions"
        fi
    fi
done
if [ -z "$errors" ]; then
    printf "%-55s %-20s\n" "Status check /etc/cron*:" "OK" >> $LOG_FILE
else
    printf "%-55s %-20s\n" "Status check /etc/cron*:" "ALERT   [ MIDDLE ]                     see $output_file_26" >> $LOG_FILE
fi



# 2.7 check /lib - 755
output_file_27="${LOG_FILE}.2.7"
dir="/lib"
expected_permissions="755"
echo -n > $output_file_27
for folder in $dir; do
    if [ -d "$folder" ]; then
        current_permissions=$(stat -c '%a' "$folder")
        if [ "$current_permissions" != "$expected_permissions" ]; then
            echo "Каталог $folder отличается от ожидаемых прав ($expected_permissions). Текущие права: $current_permissions" >> $output_file_27
            errors="$errors\nКаталог $folder отличается от ожидаемых прав ($expected_permissions). Текущие права: $current_permissions"
        fi
    fi
done
if [ -z "$errors" ]; then
    printf "%-55s %-20s\n" "Status check /lib:" "OK" >> $LOG_FILE
else
    printf "%-55s %-20s\n" "Status check /lib:" "ALERT   [ HIGH ]                     see $output_file_27" >> $LOG_FILE
fi



# 2.8 check /lib64 - 755
output_file_28="${LOG_FILE}.2.8"
dir="/lib64"
expected_permissions="755"
echo -n > $output_file_28
for folder in $dir; do
    if [ -d "$folder" ]; then
        current_permissions=$(stat -c '%a' "$folder")
        if [ "$current_permissions" != "$expected_permissions" ]; then
            echo "Каталог $folder отличается от ожидаемых прав ($expected_permissions). Текущие права: $current_permissions" >> $output_file_28
            errors="$errors\nКаталог $folder отличается от ожидаемых прав ($expected_permissions). Текущие права: $current_permissions"
        fi
    fi
done
if [ -z "$errors" ]; then
    printf "%-55s %-20s\n" "Status check /lib64:" "OK" >> $LOG_FILE
else
    printf "%-55s %-20s\n" "Status check /lib64:" "ALERT   [ HIGH ]                     see $output_file_28" >> $LOG_FILE
fi



# 2.9 check /usr/lib - 755
output_file_29="${LOG_FILE}.2.9"
dir="/usr/lib"
expected_permissions="755"
echo -n > $output_file_29
for folder in $dir; do
    if [ -d "$folder" ]; then
        current_permissions=$(stat -c '%a' "$folder")
        if [ "$current_permissions" != "$expected_permissions" ]; then
            echo "Каталог $folder отличается от ожидаемых прав ($expected_permissions). Текущие права: $current_permissions" >> $output_file_29
            errors="$errors\nКаталог $folder отличается от ожидаемых прав ($expected_permissions). Текущие права: $current_permissions"
        fi
    fi
done
if [ -z "$errors" ]; then
    printf "%-55s %-20s\n" "Status check /usr/lib:" "OK" >> $LOG_FILE
else
    printf "%-55s %-20s\n" "Status check /usr/lib:" "ALERT   [ HIGH ]                     see $output_file_29" >> $LOG_FILE
fi



# 2.10 check /usr/lib64 - 755
output_file_210="${LOG_FILE}.2.10"
dir="/usr/lib64"
expected_permissions="755"
echo -n > $output_file_210
for folder in $dir; do
    if [ -d "$folder" ]; then
        current_permissions=$(stat -c '%a' "$folder")
        if [ "$current_permissions" != "$expected_permissions" ]; then
            echo "Каталог $folder отличается от ожидаемых прав ($expected_permissions). Текущие права: $current_permissions" >> $output_file_210
            errors="$errors\nКаталог $folder отличается от ожидаемых прав ($expected_permissions). Текущие права: $current_permissions"
        fi
    fi
done
if [ -z "$errors" ]; then
    printf "%-55s %-20s\n" "Status check /usr/lib64:" "OK" >> $LOG_FILE
else
    printf "%-55s %-20s\n" "Status check /usr/lib64:" "ALERT   [ HIGH ]                     see $output_file_210" >> $LOG_FILE
fi


echo "" >> $LOG_FILE
echo "" >> $LOG_FILE


###### 3
# 3.1 "etc/ssh/sshd_config" -> PermitEmptyPasswords no
if ! grep -qE '^PermitEmptyPasswords\s+' /etc/ssh/sshd_config; then
	printf "%-55s %-20s\n" "Status PermitEmptyPasswords:" "WARNING" >> $LOG_FILE
    elif
	grep -qE '^PermitEmptyPasswords\s+no$' /etc/ssh/sshd_config; 
    then
	printf "%-55s %-20s\n" "Status PermitEmptyPasswords:" "OK" >> $LOG_FILE
    else
	printf "%-55s %-20s\n" "Status PermitEmptyPasswords:" "ALERT   [ CRITICAL ]" >> $LOG_FILE
fi


echo "" >> $LOG_FILE
echo "" >> $LOG_FILE


# 4.1 SELinux -> enable
if [[ "$(sestatus | grep 'SELinux status' | awk '{print $3}')" == "disabled" ]]; then
	printf "%-55s %-20s\n" "Status SELinux:" "ALERT   [ CRITICAL ]" >> $LOG_FILE
    else
	printf "%-55s %-20s\n" "Status SELinux:" "OK" >> $LOG_FILE
fi



# 4.2 disable ctrl-alt-del
SERVICE_NAME="ctrl-alt-del.service"
if [[ $(systemctl list-units --all | grep "$SERVICE_NAME") ]]; then
    # Сервис присутствует в списке всех юнитов systemd
    if systemctl is-enabled "$SERVICE_NAME" | grep -q disabled; then
        printf "%-55s %-20s\n" "Status disable ctrl-alt-del:" "OK" >> $LOG_FILE
    else
        printf "%-55s %-20s\n" "Status disable ctrl-alt-del:" "ALERT   [ MIDDLE ]" >> $LOG_FILE
    fi
else
	#нет в системе
    printf "%-55s %-20s\n" "Status disable ctrl-alt-del:" "OK" >> $LOG_FILE
fi



# 4.3 Поиск файлов .shosts
output_file_42="${LOG_FILE}.4.2"
files=$(find / -name ".shosts" 2>/dev/null)
if [ -n "$files" ]; then
    printf "%-55s %-20s\n" "Status Find .shosts:" "ALERT   [ HIGH ]			see $output_file_42" >> $LOG_FILE
    echo -n > $output_file_4.2
    echo "$files" >> "$output_file_42"
else
    printf "%-55s %-20s\n" "Status Find .shosts:" "OK" >> $LOG_FILE
fi



# 4.4 Availability ftp package
if yum list installed | grep -q ftp; then
#if rpm -qa | grep -qw ftp; then 
    printf "%-55s %-20s\n" "Status Availability ftp package:" "ALERT   [ MIDDLE ]" >> $LOG_FILE
else
    printf "%-55s %-20s\n" "Status Availability ftp package:" "OK" >> $LOG_FILE
fi



# 4.5 "/etc/pam.d/su" -> auth required pam_wheel.so use_uid
if grep -Pq '^\h*auth\h+required\h+pam_wheel\.so\h+use_uid\b' /etc/pam.d/su; then
#if grep -q "^auth required pam_wheel\.so use_uid$" "/etc/pam.d/su"; then
    printf "%-55s %-20s\n" "Status Mandatory Wheel affiliation:" "OK" >> $LOG_FILE
else
    printf "%-55s %-20s\n" "Status Mandatory Wheel affiliation:" "ALERT   [ HIGH ]" >> $LOG_FILE
fi
