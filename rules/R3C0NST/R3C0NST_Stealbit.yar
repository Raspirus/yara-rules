rule R3C0NST_Stealbit : FILE
{
	meta:
		description = "Detects Stealbit used by Lockbit 2.0 Ransomware Gang"
		author = "Frank Boldewin (@r3c0nst)"
		id = "07b466cb-92b3-51f2-a702-2930bb7038c6"
		date = "2021-08-12"
		modified = "2021-08-12"
		reference = "https://raw.githubusercontent.com/fboldewin/YARA-rules/master/Lockbit2.Stealbit.yar"
		source_url = "https://github.com/fboldewin/YARA-rules//blob/54e9e6899b258b72074b2b4db6909257683240c2/Lockbit2.Stealbit.yar#L1-L15"
		license_url = "N/A"
		logic_hash = "e5f770cc5887f09af0c5550073d51b9e5ffa9dcfa4db6b77bb28643f0f6224fb"
		score = 75
		quality = 90
		tags = "FILE"
		hash1 = "3407f26b3d69f1dfce76782fee1256274cf92f744c65aa1ff2d3eaaaf61b0b1d"
		hash2 = "bd14872dd9fdead89fc074fdc5832caea4ceac02983ec41f814278130b3f943e"

	strings:
		$C2Decryption = {33 C9 8B C1 83 E0 0F 8A 80 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 41 83 F9 7C 72 E9 E8}

	condition:
		uint16(0)==0x5A4D and filesize <100KB and $C2Decryption
}