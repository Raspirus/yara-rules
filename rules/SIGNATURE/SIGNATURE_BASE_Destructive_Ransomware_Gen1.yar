rule SIGNATURE_BASE_Destructive_Ransomware_Gen1 : FILE
{
	meta:
		description = "Detects destructive malware"
		author = "Florian Roth (Nextron Systems)"
		id = "3a7ce55e-fb28-577b-91bb-fe02d7b3d73c"
		date = "2018-02-12"
		modified = "2023-12-05"
		reference = "http://blog.talosintelligence.com/2018/02/olympic-destroyer.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_olympic_destroyer.yar#L13-L28"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "1f7a41c5a7e812e0e26b346cc6465290b17aff31620cbcf6e01c569d8eea2dbd"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "ae9a4e244a9b3c77d489dee8aeaf35a7c3ba31b210e76d81ef2e91790f052c85"

	strings:
		$x1 = "/set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} recoveryenabled no" fullword wide
		$x2 = "delete shadows /all /quiet" fullword wide
		$x3 = "delete catalog -quiet" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <100KB and 1 of them
}