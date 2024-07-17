rule SIGNATURE_BASE_APT_CN_Twistedpanda_Droppers : FILE
{
	meta:
		description = "Detects droppers used by TwistedPanda"
		author = "Check Point Research"
		id = "f61c8b97-5870-5837-942f-f1650870960a"
		date = "2022-04-14"
		modified = "2023-12-05"
		reference = "https://research.checkpoint.com/2022/twisted-panda-chinese-apt-espionage-operation-against-russians-state-owned-defense-institutes/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_cn_twisted_panda.yar#L157-L194"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "820b4796511dcf98cdc8017a39cc2c65e44d8d9a20f55803aa1ddd36f649c83a"
		score = 80
		quality = 85
		tags = "FILE"
		hash1 = "59dea38da6e515af45d6df68f8959601e2bbf0302e35b7989e741e9aba2f0291"
		hash2 = "8b04479fdf22892cdfebd6e6fbed180701e036806ed0ddbe79f0b29f73449248"
		hash3 = "f29a0cda6e56fc0e26efa3b6628c6bcaa0819a3275a10e9da2a8517778152d66"

	strings:
		$switch_control = { 81 FA [4] 75 ?? E8 [4] 48 89 05 [4] E? }
		$byte_manipulation = { 41 0F [2] 44 [2] 41 [2] 03 41 81 [5] 41 }
		$stack_strings_1 = { 25 00 70 00 }
		$stack_strings_2 = { 75 00 62 00 }
		$stack_strings_3 = { 6C 00 69 00 }
		$stack_strings_4 = { 63 00 25 00 }

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550 and filesize <3000KB and #switch_control>8 and all of ($stack_strings_*) and $byte_manipulation
}