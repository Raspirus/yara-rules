rule SIGNATURE_BASE_M_APT_Downloader_BEATDROP : FILE
{
	meta:
		description = "Rule looking for BEATDROP malware"
		author = "Mandiant"
		id = "5720870e-8989-59f2-998b-019084d091ce"
		date = "2022-04-28"
		modified = "2023-12-05"
		reference = "https://www.mandiant.com/resources/tracking-apt29-phishing-campaigns"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_apt29_nobelium_apr22.yar#L1-L17"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "7a766682cc9a057798cc569111bfcb611648c4a052c0dd664d983b80d5891255"
		score = 90
		quality = 85
		tags = "FILE"

	strings:
		$ntdll1 = "ntdll" ascii fullword
		$ntdll2 = "C:\\Windows\\System32\\ntdll.dll" ascii fullword nocase
		$url1 = "api.trello.com" ascii
		$url2 = "/members/me/boards?key=" ascii
		$url3 = "/cards?key=" ascii

	condition:
		uint16(0)==0x5a4d and uint32( uint32(0x3C))==0x00004550 and filesize <1MB and all of them
}