rule SIGNATURE_BASE_APT28_Skinnyboy_Dropper : RUSSIA FILE
{
	meta:
		description = "Detects APT28 SkinnyBoy droppers"
		author = "Cluster25"
		id = "ed0b2d2b-f820-57b5-9654-c24734d81996"
		date = "2021-05-24"
		modified = "2023-12-05"
		reference = "https://cluster25.io/wp-content/uploads/2021/05/2021-05_FancyBear.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_apt28.yar#L103-L118"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "9e29ed985fac8701f72f0860fe101272c3c3342ef6857e30d32f5fea14822945"
		score = 75
		quality = 85
		tags = "RUSSIA, FILE"
		hash1 = "12331809c3e03d84498f428a37a28cf6cbb1dafe98c36463593ad12898c588c9"

	strings:
		$ = "cmd /c DEL " ascii
		$ = {8a 08 40 84 c9 75 f9}
		$ = {0f b7 84 0d fc fe ff ff 66 31 84 0d fc fd ff ff}

	condition:
		( uint16(0)==0x5A4D and all of them )
}