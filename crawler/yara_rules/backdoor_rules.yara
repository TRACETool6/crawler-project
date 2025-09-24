
rule Backdoor_Patterns
{
    meta:
        description = "Detects common backdoor and RAT patterns"
        category = "backdoor"
        severity = "high"
    
    strings:
        $reverse_shell_1 = /socket\.connect\s*\(\s*\([^)]+\)\s*\)/
        $reverse_shell_2 = /subprocess\.(run|Popen|call)\s*\([^)]*shell\s*=\s*True/
        $command_exec = /exec\s*\(\s*[^)]*recv\s*\(/
        $backdoor_listen = /socket\.bind\s*\(\s*\([^)]+\)\s*\)/
        $c2_communication = /(command.{0,20}control|c2.{0,10}server)/i
        $persistence_registry = /reg\s+add.*CurrentVersion.*Run/i
        $persistence_startup = /(startup|autorun|schedule)/i
        $remote_access = /remote.{0,10}access/i
        
    condition:
        any of them
}

rule Keylogger_Patterns
{
    meta:
        description = "Detects keylogger patterns and behaviors"
        category = "keylogger"
        severity = "high"
    
    strings:
        $keylog_1 = /pynput.*keyboard/
        $keylog_2 = /on_press.*key/
        $keylog_3 = /GetAsyncKeyState/i
        $keylog_4 = /SetWindowsHookEx/i
        $keylog_5 = /keylog/i
        $clipboard_1 = /clipboard/i
        $credential_1 = /(password|credential).{0,30}(steal|extract|harvest)/i
        
    condition:
        any of them
}
