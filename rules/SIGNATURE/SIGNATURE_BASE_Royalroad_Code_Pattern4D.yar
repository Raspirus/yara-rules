
rule SIGNATURE_BASE_Royalroad_Code_Pattern4D : FILE
{
	meta:
		description = "Detects RoyalRoad weaponized RTF documents"
		author = "nao_sec"
		id = "1677dfb4-7611-5bef-87d1-4cec6285791f"
		date = "2020-01-15"
		modified = "2023-12-05"
		reference = "https://jsac.jpcert.or.jp/archive/2020/pdf/JSAC2020_8_koike-nakajima_jp.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_royalroad.yar#L113-L128"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "9b531063d2a5ae36ae4e708a749dcf2cdc4c85fc43769a8525049e6facfca674"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$S1 = "584242eb06424242353533362044606060606060606060616161616161616161616}16161616161" ascii
		$RTF = "{\\rt"

	condition:
		$RTF at 0 and $S1
}