rule SIGNATURE_BASE_CN_Disclosed_20180208_C : FILE
{
	meta:
		description = "Detects malware from disclosed CN malware set"
		author = "Florian Roth (Nextron Systems)"
		id = "cb0bcdc4-7eca-59b7-a947-85c232d4e599"
		date = "2018-02-08"
		modified = "2023-12-05"
		reference = "https://twitter.com/cyberintproject/status/961714165550342146"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_cn_campaign_njrat.yar#L28-L55"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "cfdc7ce8b89a16d2ae604268a030bd41259fed87a7f37b0dca8f7c467703c7f2"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "17475d25d40c877284e73890a9dd55fccedc6a5a071c351a8c342c8ef7f9cea7"

	strings:
		$x1 = "cmd.exe /c ping 0 -n 2 & del \"" fullword wide
		$x2 = "schtasks /create /sc minute /mo 1 /tn Server /tr " fullword wide
		$x3 = "www.upload.ee/image/" wide
		$s1 = "winmgmts:\\\\.\\root\\SecurityCenter2" fullword wide
		$s2 = "/Server.exe" fullword wide
		$s3 = "Executed As " fullword wide
		$s4 = "WmiPrvSE.exe" fullword wide
		$s5 = "Stub.exe" fullword ascii
		$s6 = "Download ERROR" fullword wide
		$s7 = "shutdown -r -t 00" fullword wide
		$s8 = "Select * From AntiVirusProduct" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <100KB and (1 of ($x*) or 4 of them )
}