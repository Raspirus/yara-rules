
rule R3C0NST_UNC2891_Slapstick : FILE
{
	meta:
		description = "Detects UNC2891 Slapstick pam backdoor"
		author = "Frank Boldewin (@r3c0nst)"
		id = "a731acff-f657-5877-859e-7447230576df"
		date = "2022-03-30"
		modified = "2023-01-05"
		reference = "https://github.com/fboldewin/YARA-rules/"
		source_url = "https://github.com/fboldewin/YARA-rules//blob/54e9e6899b258b72074b2b4db6909257683240c2/UNC2891_Slapstick.yar#L1-L19"
		license_url = "N/A"
		logic_hash = "7777c3b850f5b7ee326be5461ebc3bf37fb201b67ada78b50575fb31f50adf9a"
		score = 75
		quality = 90
		tags = "FILE"
		hash1 = "9d0165e0484c31bd4ea467650b2ae2f359f67ae1016af49326bb374cead5f789"

	strings:
		$code1 = {F6 50 04 48 FF C0 48 39 D0 75 F5}
		$code2 = {88 01 48 FF C1 8A 11 89 C8 29 F8 84 D2 0F 85}
		$str1 = "/proc/self/exe" fullword ascii
		$str2 = "%-23s %-23s %-23s %-23s %-23s %s" fullword ascii
		$str3 = "pam_sm_authenticate" ascii
		$str4 = "ACCESS GRANTED & WELCOME" xor

	condition:
		uint32(0)==0x464c457f and filesize <100KB and ( all of ($code*) or all of ($str*))
}