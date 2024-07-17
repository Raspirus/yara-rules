import "pe"


rule SIGNATURE_BASE_APT_Hiddencobra_Ghostsecret_2 : FILE
{
	meta:
		description = "Detects Hidden Cobra Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "dab5b0ec-ae89-521e-bbb9-15602db9ed6c"
		date = "2018-08-11"
		modified = "2023-12-05"
		reference = "https://securingtomorrow.mcafee.com/mcafee-labs/analyzing-operation-ghostsecret-attack-seeks-to-steal-data-worldwide/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_hidden_cobra.yar#L103-L119"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "878711f5e1a8a3cfefdaf13fc08a4778fba9d2f729248784cf72b610c8bc5e17"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "45e68dce0f75353c448865b9abafbef5d4ed6492cd7058f65bf6aac182a9176a"

	strings:
		$s1 = "ping 127.0.0.1 -n 3" fullword wide
		$s2 = "Process32" fullword ascii
		$s11 = "%2d%2d%2d%2d%2d%2d" fullword ascii
		$s12 = "del /a \"" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <400KB and all of them
}