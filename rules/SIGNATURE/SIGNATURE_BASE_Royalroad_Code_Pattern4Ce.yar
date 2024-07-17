rule SIGNATURE_BASE_Royalroad_Code_Pattern4Ce : FILE
{
	meta:
		description = "Detects RoyalRoad weaponized RTF documents"
		author = "nao_sec"
		id = "c6e8a072-23cd-5f6a-9b4f-57d3e4500d13"
		date = "2020-01-15"
		modified = "2023-12-05"
		reference = "https://jsac.jpcert.or.jp/archive/2020/pdf/JSAC2020_8_koike-nakajima_jp.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_royalroad.yar#L94-L109"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "7033c5874b406341a68f761b45fd6a9b73a9875c80b14d52a7c2240202c8fb40"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$S1 = "584242eb064242423535333620446060606060606060606161616161616161616161616}1616161" ascii
		$RTF = "{\\rt"

	condition:
		$RTF at 0 and $S1
}