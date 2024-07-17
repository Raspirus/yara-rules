rule TRELLIX_ARC_APT_Acidbox_Main_Module_Dll : BACKDOOR FILE
{
	meta:
		description = "Rule to detect the Main mode component of AcidBox"
		author = "Marc Rivero | McAfee ATR Team"
		id = "8c9beb0f-62f7-5788-8340-0b1ecdf54253"
		date = "2020-07-24"
		modified = "2020-08-14"
		reference = "https://github.com/advanced-threat-research/Yara-Rules/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/APT/APT_acidbox.yar#L34-L65"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		logic_hash = "db98e204742b8629074d47df301ffcbb2dfb977a4da91557fb50838aae79e777"
		score = 75
		quality = 70
		tags = "BACKDOOR, FILE"
		rule_version = "v1"
		malware_type = "backdoor"
		malware_family = "Backdoor:W32/Acidbox"
		actor_type = "APT"
		actor_group = "Turla"
		hash1 = "eb30a1822bd6f503f8151cb04bfd315a62fa67dbfe1f573e6fcfd74636ecedd5"

	strings:
		$pattern_0 = { 7707 b8022d03a0 eb05 e8???????? }
		$pattern_1 = { 4403c8 8bc3 41d1c6 33c6 81c6d6c162ca c1cb02 33c7 }
		$pattern_2 = { e9???????? 412b5c2418 8b45dc 412b442408 41015c241c 410144240c 015f1c }
		$pattern_3 = { 48895c2408 57 4883ec30 488bfa 33db 4885c9 7479 }
		$pattern_4 = { 48895c2408 57 4883ec30 498bd8 488bfa 488364245800 85c9 }
		$pattern_5 = { 488987e0010000 e9???????? 81cb001003a0 e9???????? 488b87a0010000 44847806 742e }
		$pattern_6 = { 4d8bcc 4c8d0596c50100 498bd4 488bce e8???????? 498b9de0010000 c74605aa993355 }
		$pattern_7 = { 4533c0 8d5608 e8???????? 488bf0 4889442460 4885c0 750b }
		$pattern_8 = { 488d5558 41c1ee08 41b802000000 44887559 e8???????? 4c8b4de0 894718 }
		$pattern_9 = { 4d03c2 4d3bc2 4d13cc 4d0303 4d3b03 4d8903 4c8b13 }

	condition:
		7 of them and filesize <550912
}