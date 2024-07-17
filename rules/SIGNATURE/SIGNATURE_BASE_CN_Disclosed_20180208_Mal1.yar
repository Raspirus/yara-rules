import "pe"


rule SIGNATURE_BASE_CN_Disclosed_20180208_Mal1 : FILE
{
	meta:
		description = "Detects malware from disclosed CN malware set"
		author = "Florian Roth (Nextron Systems)"
		id = "8516bbfb-a2ad-565d-bf6c-71629b1831a1"
		date = "2018-02-08"
		modified = "2023-12-05"
		reference = "https://www.virustotal.com/graph/#/selected/n120z79z208z189/drawer/graph-details"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_cn_campaign_njrat.yar#L77-L103"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "cf532761d07ee3e84028a9071409f081a7a85728d55c215c912f0b70902f101f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "173d69164a6df5bced94ab7016435c128ccf7156145f5d26ca59652ef5dcd24e"

	strings:
		$x1 = "%SystemRoot%\\system32\\termsrvhack.dll" fullword ascii
		$x2 = "User-Agent:Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)" fullword ascii
		$a1 = "taskkill /f /im cmd.exe" fullword ascii
		$a2 = "taskkill /f /im mstsc.exe" fullword ascii
		$a3 = "taskkill /f /im taskmgr.exe" fullword ascii
		$a4 = "taskkill /f /im regedit.exe" fullword ascii
		$a5 = "taskkill /f /im mmc.exe" fullword ascii
		$s1 = "K7TSecurity.exe" fullword ascii
		$s2 = "ServUDaemon.exe" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and (pe.imphash()=="28e3a58132364197d7cb29ee104004bf" or 1 of ($x*) or 3 of them )
}