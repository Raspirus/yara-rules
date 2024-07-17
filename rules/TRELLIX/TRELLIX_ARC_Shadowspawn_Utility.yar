import "pe"


rule TRELLIX_ARC_Shadowspawn_Utility : UTILITY FILE
{
	meta:
		description = "Rule to detect ShadowSpawn utility used in the SoftCell operation"
		author = "Marc Rivero | McAfee ATR Team"
		id = "0a325f5c-2750-5354-b920-f7e1510a8b71"
		date = "2019-06-25"
		modified = "2020-08-14"
		reference = "https://www.cybereason.com/blog/operation-soft-cell-a-worldwide-campaign-against-telecommunications-providers"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/APT/APT_Operation_SoftCell.yar#L3-L32"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		logic_hash = "0f2805aee60cdb4eb932768849c845052c92131d0b25a511b822b79b2ac93e24"
		score = 75
		quality = 70
		tags = "UTILITY, FILE"
		rule_version = "v1"
		malware_type = "utility"
		malware_family = "Trojan:W32/ShadowSpawn"
		actor_type = "Apt"
		actor_group = "Unknown"

	strings:
		$pdb = "C:\\data\\projects\\shadowspawn\\src\\bin\\Release-W2K3\\x64\\ShadowSpawn.pdb" fullword ascii
		$op0 = { e9 34 ea ff ff cc cc cc cc 48 8d 8a 20 }
		$op1 = { 48 8b 85 e0 06 00 00 48 8d 34 00 48 8d 46 02 48 }
		$op2 = { e9 34 c1 ff ff cc cc cc cc 48 8b 8a 68 }

	condition:
		uint16(0)==0x5a4d and filesize <200KB and (pe.imphash()=="eaae87b11d2ebdd286af419682037b4c" and all of them )
}