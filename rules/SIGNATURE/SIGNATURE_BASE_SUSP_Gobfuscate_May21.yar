rule SIGNATURE_BASE_SUSP_Gobfuscate_May21 : FILE
{
	meta:
		description = "Identifies binaries obfuscated with gobfuscate"
		author = "James Quinn, Paul Hager (merged with new similar pattern)"
		id = "ae518296-b1c3-568c-bae0-3e0a6f7600ba"
		date = "2021-05-14"
		modified = "2024-04-02"
		reference = "https://github.com/unixpickle/gobfuscate"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_gobfuscate.yar#L2-L18"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "f71078dd6354a482a2ead2f0d25f4172cd40e62440a70c2da7916b68f26909a3"
		score = 70
		quality = 85
		tags = "FILE"

	strings:
		$s1 = { 0F B6 ?? ?? ?? 0F B6 ?? ?? ?? 31 D? [0-1] 88 ?? ?? ?? 48 FF C? 48 83 F? ?? 7C E6 48 }
		$s2 = { 0F B6 ?? ?? ?? 31 DA 88 ?? ?? ?? 40 83 ?? ?? 7D 09 0F B6 }

	condition:
		filesize <50MB and any of them
}