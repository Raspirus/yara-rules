rule SIGNATURE_BASE_APT_Hiddencobra_Ghostsecret_1 : FILE
{
	meta:
		description = "Detects Hidden Cobra Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "d6955294-84a4-5694-87c9-b5b1c39e0fae"
		date = "2018-08-11"
		modified = "2023-12-05"
		reference = "https://securingtomorrow.mcafee.com/mcafee-labs/analyzing-operation-ghostsecret-attack-seeks-to-steal-data-worldwide/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_hidden_cobra.yar#L87-L101"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "b1e72ca66520152b444cc415bdf54921ebba9671519d3b0327316cee2bf0ba1d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "05a567fe3f7c22a0ef78cc39dcf2d9ff283580c82bdbe880af9549e7014becfc"

	strings:
		$s1 = "%s\\%s.dll" fullword wide
		$s2 = "PROXY_SVC_DLL.dll" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and all of them
}