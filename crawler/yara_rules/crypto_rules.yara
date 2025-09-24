
rule Cryptocurrency_Miner
{
    meta:
        description = "Detects cryptocurrency mining patterns"
        category = "cryptominer"
        severity = "medium"
    
    strings:
        $mining_1 = /(bitcoin|ethereum|monero|litecoin).{0,20}(mine|mining|miner)/i
        $mining_2 = /mining.{0,20}pool/i
        $mining_3 = /stratum\+tcp/i
        $mining_4 = /hashrate/i
        $mining_5 = /cryptonight/i
        $mining_6 = /sha256.*nonce/i
        $wallet_1 = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ // Bitcoin address
        $wallet_2 = /0x[a-fA-F0-9]{40}/ // Ethereum address
        $cryptojacking = /cryptojacking/i
        
    condition:
        any of them
}

rule Steganography_Hiding
{
    meta:
        description = "Detects steganography and data hiding techniques"
        category = "evasion"
        severity = "medium"
    
    strings:
        $stego_1 = /steganography/i
        $stego_2 = /hide.{0,20}(data|payload)/i
        $stego_3 = /embed.{0,20}(data|code)/i
        $obfuscation = /obfuscat/i
        $base64_suspicious = /base64.*exec/i
        $hex_decode = /hex.*decode.*exec/i
        
    condition:
        any of them
}
