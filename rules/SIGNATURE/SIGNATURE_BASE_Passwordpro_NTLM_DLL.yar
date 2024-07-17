rule SIGNATURE_BASE_Passwordpro_NTLM_DLL : FILE
{
	meta:
		description = "Auto-generated rule - file NTLM.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "cc86b868-000f-56b1-91cd-4aa8caace1df"
		date = "2017-08-27"
		modified = "2023-12-05"
		reference = "PasswordPro"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/thor-hacktools.yar#L3944-L3962"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "1021fe1a4c7a237d7a7cfcb1db8fa5e6fa640d3dd9f14ed37910a6b847717d36"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "47d4755d31bb96147e6230d8ea1ecc3065da8e557e8176435ccbcaea16fe50de"

	strings:
		$s1 = "NTLM.dll" fullword ascii
		$s2 = "Algorithm: NTLM" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <20KB and pe.exports("GetHash") and pe.exports("GetInfo") and ( all of them ))
}