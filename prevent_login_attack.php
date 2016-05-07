<?php
/**
 * Prevent ssh login attack
 * Author : Geniusking
 * Date: 2016-05-06
 */

define("LIMITS", 10);
define("ATTACK_PATTEN", "Failed password for root from");
define("LOG_PATH", "/var/log/auth.log");
define("IP_COLUMN", 11);

/** Get the IPs*/
$ips = shell_exec(sprintf("grep '%s' %s | awk '{print $%s}'", ATTACK_PATTEN, LOG_PATH, IP_COLUMN));

$arr_ips = explode("\n", $ips);
$pool = array();
foreach ($arr_ips as $ip) {
    @$pool[$ip] += 1;
}

echo $iptables_list = shell_exec("/sbin/iptables -L -n");

foreach ($pool as $ip => $counts) {

    if (!empty($ip) && preg_match("/$ip/is", $iptables_list, $o) == false) {

        if ($counts > LIMITS) {
            echo $cmd = sprintf("/sbin/iptables -I INPUT -s %s -j DROP\n", $ip);
            shell_exec($cmd);
        }
    }
}
print_r($pool);

echo shell_exec("/sbin/iptables -L -n");
