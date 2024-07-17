
rule SIGNATURE_BASE_WEBSHELL_Compiled_Webshell_Mar2021_1 : FILE
{
	meta:
		description = "Triggers on temporary pe files containing strings commonly used in webshells."
		author = "Bundesamt fuer Sicherheit in der Informationstechnik"
		id = "9336bd2c-791c-5c3e-9733-724a6a23864a"
		date = "2021-03-05"
		modified = "2021-03-12"
		reference = "https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Cyber-Sicherheit/Vorfaelle/Exchange-Schwachstellen-2021/MSExchange_Schwachstelle_Detektion_Reaktion.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_hafnium.yar#L275-L295"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "d2e5f91f7bb50984c491eb9632d3863febc986760e4d03c8255872887ce4dc4a"
		score = 75
		quality = 81
		tags = "FILE"

	strings:
		$x1 = /App_Web_[a-zA-Z0-9]{7,8}.dll/ ascii wide fullword
		$a1 = "~/aspnet_client/" ascii wide nocase
		$a2 = "~/auth/" ascii wide nocase
		$b1 = "JScriptEvaluate" ascii wide fullword
		$c1 = "get_Request" ascii wide fullword
		$c2 = "get_Files" ascii wide fullword
		$c3 = "get_Count" ascii wide fullword
		$c4 = "get_Item" ascii wide fullword
		$c5 = "get_Server" ascii wide fullword

	condition:
		uint16(0)==0x5a4d and filesize >5KB and filesize <40KB and all of ($x*) and 1 of ($a*) and ( all of ($b*) or all of ($c*))
}