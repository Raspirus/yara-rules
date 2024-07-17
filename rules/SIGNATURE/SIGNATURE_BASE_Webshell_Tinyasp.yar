
rule SIGNATURE_BASE_Webshell_Tinyasp : FILE
{
	meta:
		description = "Detects 24 byte ASP webshell and variations"
		author = "Jeff Beley"
		id = "38b1f61b-e506-59b2-9157-d0345431c429"
		date = "2019-01-09"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/thor-webshells.yar#L9899-L9910"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "d8b7db89ea623d5bcf14476779df727827cfc752d4c6ba4208445fd7305e6943"
		score = 75
		quality = 83
		tags = "FILE"
		hash1 = "1f29905348e136b66d4ff6c1494d6008ea13f9551ad5aa9b991893a31b37e452"

	strings:
		$s1 = "Execute Request" ascii wide nocase

	condition:
		uint16(0)==0x253c and filesize <150 and 1 of them
}