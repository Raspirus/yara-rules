rule SIGNATURE_BASE_APT_NK_Scarcruft_RUBY_Shellcode_XOR_Routine : APT
{
	meta:
		description = "Detects Ruby ShellCode XOR routine used by ScarCruft APT group"
		author = "S2WLAB_TALON_JACK2"
		id = "c393f2db-8ade-5083-9cec-f62f23056f8b"
		date = "2021-05-20"
		modified = "2023-12-05"
		reference = "https://medium.com/s2wlab/matryoshka-variant-of-rokrat-apt37-scarcruft-69774ea7bf48"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_nk_inkysquid.yar#L104-L133"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "a97041a06729d639c22a4ee272cc96555345b692fc0da8b62e898891d02b23ea"
		score = 75
		quality = 85
		tags = "APT"
		type = "APT"
		version = "0.1"

	strings:
		$hex1 = {C1 C7 0D 40 F6 C7 01 74 ?? 81 F7}
		$hex2 = {41 C1 C2 0D 41 8B C2 44 8B CA 41 8B CA 41 81 F2}

	condition:
		1 of them
}