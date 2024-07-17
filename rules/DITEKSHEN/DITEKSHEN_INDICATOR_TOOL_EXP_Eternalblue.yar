import "pe"


rule DITEKSHEN_INDICATOR_TOOL_EXP_Eternalblue : FILE
{
	meta:
		description = "Detects Windows executables containing EternalBlue explitation artifacts"
		author = "ditekSHen"
		id = "08173a1e-2e32-5add-864a-d92ffa0a3e44"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L322-L342"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "63e56637118accb8c32c20e52465c027df2dbf83b3b663d316b453ce879572c8"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$ci1 = "CNEFileIO_" ascii wide
		$ci2 = "coli_" ascii wide
		$ci3 = "mainWrapper" ascii wide
		$dp1 = "EXPLOIT_SHELLCODE" ascii wide
		$dp2 = "ETERNALBLUE_VALIDATE_BACKDOOR" ascii wide
		$dp3 = "ETERNALBLUE_DOUBLEPULSAR_PRESENT" ascii wide
		$dp4 = "//service[name='smb']/port" ascii wide
		$dp5 = /DOUBLEPULSAR_(PROTOCOL_|ARCHITECTURE_|FUNCTION_|DLL_|PROCESS_|COMMAND_|IS_64_BIT)/
		$cm1 = "--DllOrdinal 1 ProcessName lsass.exe --ProcessCommandLine --Protocol SMB --Architecture x64 --Function Rundll" ascii wide
		$cm2 = "--DllOrdinal 1 ProcessName lsass.exe --ProcessCommandLine --Protocol SMB --Architecture x86 --Function Rundll" ascii wide
		$cm3 = "--DaveProxyPort=0 --NetworkTimeout 30 --TargetPort 445 --VerifyTarget True --VerifyBackdoor True --MaxExploitAttempts 3 --GroomAllocations 12 --OutConfig" ascii wide

	condition:
		uint16(0)==0x5a4d and (2 of ($ci*)) or (2 of ($dp*)) or (1 of ($dp*) and 1 of ($ci*)) or (1 of ($cm*))
}