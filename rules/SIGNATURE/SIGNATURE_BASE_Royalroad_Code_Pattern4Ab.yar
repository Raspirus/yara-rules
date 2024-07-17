rule SIGNATURE_BASE_Royalroad_Code_Pattern4Ab : FILE
{
	meta:
		description = "Detects RoyalRoad weaponized RTF documents"
		author = "nao_sec"
		id = "b4926888-b576-59f7-932a-03b9326845da"
		date = "2020-01-15"
		modified = "2023-12-05"
		reference = "https://jsac.jpcert.or.jp/archive/2020/pdf/JSAC2020_8_koike-nakajima_jp.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_royalroad.yar#L77-L92"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "dd9468b3208a27b6f3b56037013f06c4d2adbd201a12df141bc980ad595a75c0"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$S1 = "4746424151515151505050500000000000584242EB064242423535333620446060606060606060606161616161616}1616161616161616161" ascii
		$RTF = "{\\rt"

	condition:
		$RTF at 0 and $S1
}