rule SIGNATURE_BASE_MAL_UNC2891_Slapstick : FILE
{
	meta:
		description = "Detects UNC2891 Slapstick pam backdoor"
		author = "Frank Boldewin (@r3c0nst), slightly modifier by Florian Roth"
		id = "eb5db507-ac12-5c11-9dd9-ec34b9a80e1c"
		date = "2022-03-30"
		modified = "2023-01-05"
		reference = "https://github.com/fboldewin/YARA-rules/tree/master"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_unc2891_mal_jan23.yar#L19-L39"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "4bc51a47a1b620c3bb950c287c38a37e528e79f9720fb4d9fa9ebecbeca82036"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "9d0165e0484c31bd4ea467650b2ae2f359f67ae1016af49326bb374cead5f789"

	strings:
		$code1 = {F6 50 04 48 FF C0 48 39 D0 75 F5}
		$code2 = {88 01 48 FF C1 8A 11 89 C8 29 F8 84 D2 0F 85}
		$str1 = "/proc/self/exe" fullword ascii
		$str2 = "%-23s %-23s %-23s %-23s %-23s %s" fullword ascii
		$str3 = "pam_sm_authenticate" ascii
		$str_fr1 = "HISTFILE=/dev/null"

	condition:
		uint32(0)==0x464c457f and filesize <100KB and ( all of ($code*) or all of ($str*))
}