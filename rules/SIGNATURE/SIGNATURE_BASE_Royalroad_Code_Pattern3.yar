
rule SIGNATURE_BASE_Royalroad_Code_Pattern3 : FILE
{
	meta:
		description = "Detects RoyalRoad weaponized RTF documents"
		author = "nao_sec"
		id = "7bce2fe6-a921-51ec-8b5f-5d7f55ab3864"
		date = "2020-01-15"
		modified = "2023-12-05"
		reference = "https://jsac.jpcert.or.jp/archive/2020/pdf/JSAC2020_8_koike-nakajima_jp.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_royalroad.yar#L59-L75"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "3b5d9872eb86d1a220e5b70c560e7054bee8b2bc1fa2a75781d87616674e2927"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$S1 = "4746424151515151505050500000000000584242eb0642424235353336204460606060606060606061616161616161616161616161616161"
		$RTF = "{\\rt"

	condition:
		$RTF at 0 and $S1
}