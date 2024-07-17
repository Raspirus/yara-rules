import "pe"


rule DITEKSHEN_INDICATOR_TOOL_SCN_Smbtouch : FILE
{
	meta:
		description = "Detects SMBTouch scanner EternalBlue, EternalChampion, EternalRomance, EternalSynergy"
		author = "ditekSHen"
		id = "4e8176dd-4113-5fa8-a695-77e7169f6975"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L376-L400"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "78c2a435762d3febe927eb15910d5a18c1ffe74604673463543d3c859f5ef8e9"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "[+] SMB Touch started" fullword ascii
		$s2 = "[-] Could not connect to share (0x%08X - %s)" fullword ascii
		$s3 = "[!] Target could be either SP%d or SP%d," fullword ascii
		$s4 = "[!] for these SMB exploits they are equivalent" fullword ascii
		$s5 = "[+] Target is vulnerable to %d exploit%s" fullword ascii
		$s6 = "[+] Touch completed successfully" fullword ascii
		$s7 = "Network error while determining exploitability" fullword ascii
		$s8 = "Named pipe or share required for exploit" fullword ascii
		$w1 = "UsingNbt" fullword ascii
		$w2 = "TargetPort" fullword ascii
		$w3 = "TargetIp" fullword ascii
		$w4 = "RedirectedTargetPort" fullword ascii
		$w5 = "RedirectedTargetIp" fullword ascii
		$w6 = "NtlmHash" fullword ascii
		$w7 = "\\PIPE\\LANMAN" fullword ascii
		$w8 = "UserRejected: " fullword ascii

	condition:
		uint16(0)==0x5a4d and (2 of ($s*) or all of ($w*))
}