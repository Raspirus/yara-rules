import "pe"


rule SIGNATURE_BASE_MAL_Winnti_BR_Report_Mockingjay : FILE
{
	meta:
		description = "Detects Winnti samples"
		author = "@br_data repo"
		id = "9aff9d65-3827-59de-9dc3-38f227155d3d"
		date = "2019-07-24"
		modified = "2023-12-05"
		reference = "https://github.com/br-data/2019-winnti-analyse"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_winnti_br.yar#L30-L46"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "7a63b6f10cc5feebba16e585cb29d741876e1dc7f4dde3ef43ac76db9c7ad135"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$load_magic = { C7 44 ?? ?? FF D8 FF E0 }
		$iter = { E9 EA EB EC ED EE EF F0 }
		$jpeg = { FF D8 FF E0 00 00 00 00 00 00 }

	condition:
		uint16(0)==0x5a4d and $jpeg and ($load_magic or $iter in (@jpeg[1]..@jpeg[1]+200)) and for any i in (1..#jpeg) : ( uint8(@jpeg[i]+11)!=0)
}