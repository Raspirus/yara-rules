
rule SIGNATURE_BASE_APT_NK_Lazarus_RC4_Loop : FILE
{
	meta:
		description = "Detects RC4 loop in Lazarus Group implant"
		author = "f-secure "
		id = "a9503795-b4b8-505e-a1bf-df64ec8c1c32"
		date = "2020-06-10"
		modified = "2023-12-05"
		reference = "https://labs.f-secure.com/publications/ti-report-lazarus-group-cryptocurrency-vertical"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_lazarus_aug20.yar#L2-L15"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "b0e96bfff924a0c9b39e1ab03097ae0790743417d9da70917d64bc238905971e"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$str_rc4_loop = { 41 FE 8? 00 01 00 00 45 0F B6 ?? 00 01 00 00 48 
                        FF C? 43 0F B6 0? ?? 41 00 8? 01 01 00 00 41 0F 
                        B6 ?? 01 01 00 00 }

	condition:
		int16 (0)==0x5a4d and filesize <3000KB and $str_rc4_loop
}