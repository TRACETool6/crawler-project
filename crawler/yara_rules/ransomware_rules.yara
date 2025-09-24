
rule Ransomware_Patterns
{
    meta:
        description = "Detects ransomware patterns and behaviors"
        category = "ransomware"
        severity = "critical"
    
    strings:
        $encrypt_1 = /encrypt.{0,30}files?/i
        $encrypt_2 = /AES|Fernet|cipher/
        $ransom_1 = /(ransom|decrypt).{0,30}(note|message|instructions)/i
        $ransom_2 = /pay.{0,20}bitcoin/i
        $ransom_3 = /files?.{0,20}encrypted/i
        $file_ext_change = /\.(locked|encrypted|crypto|vault)/
        $bitcoin_demand = /[0-9.]+\s*(BTC|bitcoin)/i
        $tor_contact = /\.onion/
        $file_destruction = /remove|delete.*original/i
        
    condition:
        2 of them
}

rule Network_Scanner_Botnet
{
    meta:
        description = "Detects network scanning and botnet patterns"
        category = "botnet"
        severity = "high"
    
    strings:
        $botnet_1 = /botnet/i
        $ddos_1 = /(ddos|dos).{0,20}attack/i
        $ddos_2 = /flood.{0,20}(target|server)/i
        $port_scan = /port.{0,20}scan/i
        $network_scan = /nmap|masscan/i
        $irc_bot = /irc.{0,30}(bot|command)/i
        $zombie = /zombie/i
        
    condition:
        any of them
}
