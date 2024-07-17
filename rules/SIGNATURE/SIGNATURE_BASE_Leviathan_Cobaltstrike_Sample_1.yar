
rule SIGNATURE_BASE_Leviathan_Cobaltstrike_Sample_1 : FILE
{
	meta:
		description = "Detects Cobalt Strike sample from Leviathan report"
		author = "Florian Roth (Nextron Systems)"
		id = "e29072d8-b4ea-5e94-8a1c-0a1baec5f423"
		date = "2017-10-18"
		modified = "2023-12-05"
		reference = "https://goo.gl/MZ7dRg"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_leviathan.yar#L33-L55"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "9ebc8c2f8ddba302e0fbde69e27986236053a3d31c50cf3a2f979a9ebb90907f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "5860ddc428ffa900258207e9c385f843a3472f2fbf252d2f6357d458646cf362"

	strings:
		$x1 = "a54c81.dll" fullword ascii
		$x2 = "%d is an x64 process (can't inject x86 content)" fullword ascii
		$x3 = "Failed to impersonate logged on user %d (%u)" fullword ascii
		$s1 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" fullword ascii
		$s2 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/'); %s" fullword ascii
		$s3 = "could not run command (w/ token) because of its length of %d bytes!" fullword ascii
		$s4 = "could not write to process memory: %d" fullword ascii
		$s5 = "%s.4%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" fullword ascii
		$s6 = "Could not connect to pipe (%s): %d" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <600KB and (1 of ($x*) or 3 of them )
}