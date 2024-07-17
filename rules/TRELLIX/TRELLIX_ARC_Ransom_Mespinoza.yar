rule TRELLIX_ARC_Ransom_Mespinoza : FILE
{
	meta:
		description = "rule to detect Mespinoza ransomware"
		author = "Christiaan Beek @ McAfee ATR"
		id = "70a76bc4-e0cb-5caa-bb64-1a732349d2ce"
		date = "2020-11-24"
		modified = "2020-11-24"
		reference = "https://github.com/advanced-threat-research/Yara-Rules/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/ransomware/Ransom_Mespinoza.yar#L3-L27"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		logic_hash = "e245fb9a71d86209690a6f4c7aa38c10dbd32cda2ea3ecde08d0d94e896381cb"
		score = 75
		quality = 70
		tags = "FILE"
		malware_family = "ransom_Win_Mespinoza"
		hash1 = "e9662b468135f758a9487a1be50159ef57f3050b753de2915763b4ed78839ead"
		hash2 = "48355bd2a57d92e017bdada911a4b31aa7225c0b12231c9cbda6717616abaea3"
		hash3 = "e4287e9708a73ce6a9b7a3e7c72462b01f7cc3c595d972cf2984185ac1a3a4a8"

	strings:
		$s1 = "update.bat" fullword ascii
		$s2 = "protonmail.com" fullword ascii
		$s3 = "Every byte on any types of your devices was encrypted." fullword ascii
		$s4 = "To get all your data back contact us:" fullword ascii
		$s5 = "What to do to get all data back?" fullword ascii
		$s6 = "Don't try to use backups because it were encrypted too." fullword ascii
		$op0 = { 83 f8 4b 75 9e 0f be 46 ff 8d 4d e0 ff 34 85 50 }
		$op1 = { c6 05 34 9b 47 00 00 e8 1f 0c 03 00 59 c3 cc cc }
		$op2 = { e8 ef c5 fe ff b8 ff ff ff 7f eb 76 8b 4d 0c 85 }

	condition:
		( uint16(0)==0x5a4d and filesize <600KB and pe.imphash()=="b5e8bd2552848bb7bf2f28228d014742" and (8 of them ) and 2 of ($op*)) or ( all of them )
}