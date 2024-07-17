
rule SIGNATURE_BASE_APT_CN_Twistedpanda_SPINNER_2 : FILE
{
	meta:
		description = "Detects an older variant of SPINNER payload used by TwistedPanda"
		author = "Check Point Research"
		id = "bbbf3af1-127f-5d32-967f-bdb94311d1d6"
		date = "2022-04-14"
		modified = "2023-12-05"
		reference = "https://research.checkpoint.com/2022/twisted-panda-chinese-apt-espionage-operation-against-russians-state-owned-defense-institutes/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_cn_twisted_panda.yar#L82-L118"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "d1e34903e58fb76671a076acbb9f26e10d511c8f00be90b4901d61b73b90a9a7"
		score = 80
		quality = 85
		tags = "FILE"
		hash1 = "28ecd1127bac08759d018787484b1bd16213809a2cc414514dc1ea87eb4c5ab8"

	strings:
		$config_init = { C7 [3] 00 00 00 C7 [3] 00 00 00 C6 }
		$c2_cmd_1 = { 01 00 03 10 }
		$c2_cmd_2 = { 02 00 01 10 }
		$c2_cmd_3 = { 01 00 01 10 }
		$c2_cmd_4 = { 01 00 00 10 }
		$c2_cmd_5 = { 02 00 00 10 }
		$decryption = { 80 B3 [5] 8D BB [4] 8B 56 14 8B C2 8B 4E 10 2B C1 83 F8 01 }

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550 and filesize <3000KB and #config_init>10 and 2 of ($c2_cmd_*) and $decryption
}