import "pe"


rule SIGNATURE_BASE_APT_APT41_HIGHNOON : FILE
{
	meta:
		description = "Detects APT41 malware HIGHNOON"
		author = "Florian Roth (Nextron Systems)"
		id = "6611fb04-7237-52d1-b29f-941c3853aeca"
		date = "2019-08-07"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_apt41.yar#L108-L135"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "c8afa91f90157c3ac0f7954cd2d42022392c4e6f039d88d1dd4bace19028c2b1"
		score = 85
		quality = 85
		tags = "FILE"
		hash1 = "63e8ed9692810d562adb80f27bb1aeaf48849e468bf5fd157bc83ca83139b6d7"
		hash2 = "4aa6970cac04ace4a930de67d4c18106cf4004ba66670cfcdaa77a4c4821a213"

	strings:
		$x1 = "workdll64.dll" fullword ascii
		$s1 = "\\Fonts\\Error.log" ascii
		$s2 = "[%d/%d/%d/%d:%d:%d]" fullword ascii
		$s3 = "work_end" fullword ascii
		$s4 = "work_start" fullword ascii
		$s5 = "\\svchost.exe" ascii
		$s6 = "LoadAppInit_DLLs" fullword ascii
		$s7 = "netsvcs" fullword ascii
		$s8 = "HookAPIs ...PID %d " fullword ascii
		$s9 = "SOFTWARE\\Microsoft\\HTMLHelp" fullword ascii
		$s0 = "DllMain_mem" fullword ascii
		$s10 = "%s\\NtKlRes.dat" fullword ascii
		$s11 = "Global\\%s-%d" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and (1 of ($x*) or 4 of them )
}