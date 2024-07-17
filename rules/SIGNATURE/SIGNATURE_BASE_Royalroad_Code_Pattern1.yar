rule SIGNATURE_BASE_Royalroad_Code_Pattern1 : FILE
{
	meta:
		description = "Detects RoyalRoad weaponized RTF documents"
		author = "nao_sec"
		id = "db2fb24c-df99-5622-ac3d-d31c34481984"
		date = "2020-01-15"
		modified = "2023-12-05"
		reference = "https://jsac.jpcert.or.jp/archive/2020/pdf/JSAC2020_8_koike-nakajima_jp.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_royalroad.yar#L25-L40"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "ebd507d95c454562fa0b364072120b35b1bf8dd2be129a419d893f6708ab9cca"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$S1 = "48905d006c9c5b0000000000030101030a0a01085a5ab844eb7112ba7856341231"
		$RTF = "{\\rt"

	condition:
		$RTF at 0 and $S1
}