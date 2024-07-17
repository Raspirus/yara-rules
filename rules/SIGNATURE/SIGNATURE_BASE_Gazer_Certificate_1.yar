rule SIGNATURE_BASE_Gazer_Certificate_1 : FILE
{
	meta:
		description = "Detects Tura's Gazer malware"
		author = "ESET"
		id = "4eace653-003e-5cae-9db8-f26502f35fc4"
		date = "2017-08-30"
		modified = "2023-12-05"
		reference = "https://www.welivesecurity.com/2017/08/30/eset-research-cyberespionage-gazer/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_turla_gazer.yar#L27-L39"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "ef248ac5cdde0034d940f80b32966fe64841dcf99923dfc0a7035354af963f56"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$certif1 = { 52 76 a4 53 cd 70 9c 18 da 65 15 7e 5f 1f de 02 }
		$certif2 = { 12 90 f2 41 d9 b2 80 af 77 fc da 12 c6 b4 96 9c }

	condition:
		uint16(0)==0x5a4d and 1 of them and filesize <2MB
}