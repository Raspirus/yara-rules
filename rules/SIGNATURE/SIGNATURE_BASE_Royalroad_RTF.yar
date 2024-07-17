rule SIGNATURE_BASE_Royalroad_RTF : FILE
{
	meta:
		description = "Detects RoyalRoad weaponized RTF documents"
		author = "nao_sec"
		id = "366ec9c3-e6ad-5198-88d5-15aa84a8358f"
		date = "2020-01-15"
		modified = "2023-12-05"
		reference = "https://jsac.jpcert.or.jp/archive/2020/pdf/JSAC2020_8_koike-nakajima_jp.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_royalroad.yar#L133-L148"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "20031fe6d6a0b2fad43f7e04bb82321c2ea75193f23194edead7ca530af8ac55"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$S1 = "objw2180\\objh300" ascii
		$RTF = "{\\rt"

	condition:
		$RTF at 0 and $S1
}