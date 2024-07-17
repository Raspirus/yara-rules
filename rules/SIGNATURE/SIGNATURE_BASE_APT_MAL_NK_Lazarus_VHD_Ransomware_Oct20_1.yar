rule SIGNATURE_BASE_APT_MAL_NK_Lazarus_VHD_Ransomware_Oct20_1 : FILE
{
	meta:
		description = "Detects Lazarus VHD Ransomware"
		author = "Florian Roth (Nextron Systems)"
		id = "5cb3c136-ec5c-5596-8dcc-e4c6ef33050a"
		date = "2020-10-05"
		modified = "2023-12-05"
		reference = "https://securelist.com/lazarus-on-the-hunt-for-big-game/97757/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_lazarus_vhd_ransomware.yar#L2-L24"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "95c56c5111bb227da8f8a3f8aa4f23e1348bc76ff76a05fc3cae89f9fad1bb52"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "52888b5f881f4941ae7a8f4d84de27fc502413861f96ee58ee560c09c11880d6"
		hash2 = "5e78475d10418c6938723f6cfefb89d5e9de61e45ecf374bb435c1c99dd4a473"
		hash3 = "6cb9afff8166976bd62bb29b12ed617784d6e74b110afcf8955477573594f306"

	strings:
		$s1 = "HowToDecrypt.txt" wide fullword
		$s2 = "rsa.cpp" wide fullword
		$s3 = "sc stop \"Microsoft Exchange Compliance Service\"" ascii fullword
		$op1 = { 8b 8d bc fc ff ff 8b 94 bd 34 03 00 00 33 c0 50 }
		$op2 = { 8b 8d 98 f9 ff ff 8d 64 24 00 8b 39 3b bc 85 34 }
		$op3 = { 8b 94 85 34 03 00 00 89 11 40 83 c1 04 3b 06 7c }

	condition:
		uint16(0)==0x5a4d and filesize <400KB and 2 of them
}