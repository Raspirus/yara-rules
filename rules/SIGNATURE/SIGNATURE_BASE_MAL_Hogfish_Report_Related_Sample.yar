rule SIGNATURE_BASE_MAL_Hogfish_Report_Related_Sample : FILE
{
	meta:
		description = "Detects APT10 / Hogfish related samples"
		author = "Florian Roth (Nextron Systems)"
		id = "7fc4fdda-b71f-5c9c-87a4-5d8290b99348"
		date = "2018-05-01"
		modified = "2023-12-05"
		reference = "https://www.accenture.com/t20180423T055005Z__w__/se-en/_acnmedia/PDF-76/Accenture-Hogfish-Threat-Analysis.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_apt10_redleaves.yar#L13-L31"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "bff74f7a72a3e40e828284ed37b2f7ea64d8df52e946372d38e379d9b7b7a445"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "f9acc706d7bec10f88f9cfbbdf80df0d85331bd4c3c0188e4d002d6929fe4eac"
		hash2 = "7188f76ca5fbc6e57d23ba97655b293d5356933e2ab5261e423b3f205fe305ee"
		hash3 = "4de5a22cd798950a69318fdcc1ec59e9a456b4e572c2d3ac4788ee96a4070262"

	strings:
		$s1 = "R=user32.dll" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and (pe.imphash()=="efad9ff8c0d2a6419bf1dd970bcd806d" or 1 of them )
}