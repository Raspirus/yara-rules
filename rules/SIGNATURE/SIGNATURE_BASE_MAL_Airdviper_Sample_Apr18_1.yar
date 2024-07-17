import "pe"


rule SIGNATURE_BASE_MAL_Airdviper_Sample_Apr18_1 : FILE
{
	meta:
		description = "Detects Arid Viper malware sample"
		author = "Florian Roth (Nextron Systems)"
		id = "00f118d1-be1c-5f50-a50f-591f824a1a53"
		date = "2018-05-04"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_winnti_burning_umbrella.yar#L398-L422"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "cbe1f36320eb9640ffbb6495faf7e5a062c5929d022bb56cbf0ebee810ef4e94"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "9f453f1d5088bd17c60e812289b4bb0a734b7ad2ba5a536f5fd6d6ac3b8f3397"

	strings:
		$x1 = "cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del \"%s\"" fullword ascii
		$x2 = "daenerys=%s&" ascii
		$x3 = "betriebssystem=%s&anwendung=%s&AV=%s" ascii
		$s1 = "Taskkill /IM  %s /F &  %s" fullword ascii
		$s2 = "/api/primewire/%s/requests/macKenzie/delete" fullword ascii
		$s3 = "\\TaskWindows.exe" ascii
		$s4 = "MicrosoftOneDrives.exe" fullword ascii
		$s5 = "\\SeanSansom.txt" ascii

	condition:
		uint16(0)==0x5a4d and filesize <6000KB and (1 of ($x*) or 4 of them )
}