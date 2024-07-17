
rule SIGNATURE_BASE_APT_CN_Twistedpanda_SPINNER_1 : FILE
{
	meta:
		description = "Detects the obfuscated variant of SPINNER payload used by TwistedPanda"
		author = "Check Point Research"
		id = "0b44013d-0caa-5ea2-ab08-e2a6a5732c03"
		date = "2022-04-14"
		modified = "2023-12-05"
		reference = "https://research.checkpoint.com/2022/twisted-panda-chinese-apt-espionage-operation-against-russians-state-owned-defense-institutes/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_cn_twisted_panda.yar#L46-L80"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "e7abe4b3f4225596131882a9175f9ac2e45ba00557950772a8e4d1eaeab97d05"
		score = 80
		quality = 85
		tags = "FILE"
		hash1 = "a9fb7bb40de8508606a318866e0e5ff79b98f314e782f26c7044622939dfde81"

	strings:
		$config_init = { C7 ?? ?? ?? 00 00 00 C7 ?? ?? ?? 00 00 00 C6 }
		$c2_cmd_1 = { 01 00 03 10}
		$c2_cmd_2 = { 02 00 01 10}
		$c2_cmd_3 = { 01 00 01 10}
		$decryption = { 8D 83 [4] 80 B3 [5] 89 F1 6A 01 50 E8 [4] 80 B3 }

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550 and filesize <3000KB and #config_init>10 and 2 of ($c2_cmd_*) and $decryption
}