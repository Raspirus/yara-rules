rule VOLEXITY_General_Jsp_Possible_Tiny_Fileuploader : GENERAL WEBSHELLS FILE
{
	meta:
		description = "Detects small .jsp files which have possible file upload utility."
		author = "threatintel@volexity.com"
		id = "d111aab3-af6e-59cb-a445-ebd4a454fb9a"
		date = "2022-06-01"
		modified = "2022-06-06"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2022/2022-06-02 Active Exploitation Of Confluence 0-day/indicators/yara.yar#L17-L50"
		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
		logic_hash = "bad62e6fd33ffb0d8551302fd7f85528066992c272b670d44a33b5b2eb174886"
		score = 75
		quality = 80
		tags = "GENERAL, WEBSHELLS, FILE"
		hash1 = "4addb9bc9e5e1af8fda63589f6b3fc038ccfd651230fa3fa61814ad080e95a12"
		memory_suitable = 0
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$required1 = "request." ascii
		$required2 = "java.io.FileOutputStream" ascii
		$required3 = ".write" ascii
		$encoding1 = "java.util.Base64" ascii
		$encoding2 = "crypto.Cipher" ascii
		$encoding3 = ".misc.BASE64Decoder" ascii

	condition:
		( filesize <4KB and all of ($required*) and any of ($encoding*)) or ( filesize <600 and all of ($required*))
}