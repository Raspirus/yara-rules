rule VOLEXITY_Webshell_Jsp_General_Runtime_Exec_Req : GENERAL WEBSHELLS
{
	meta:
		description = "Looks for a common design pattern in webshells where a request attribute is passed directly to exec()."
		author = "threatintel@volexity.com"
		id = "7f1539bd-a2f0-50dd-b500-ada4e0971d13"
		date = "2022-02-02"
		modified = "2022-08-10"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2022/2022-08-10 Mass exploitation of (Un)authenticated Zimbra RCE CVE-2022-27925/yara.yar#L30-L45"
		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
		logic_hash = "d3048aba80c1c39f1673931cd2d7c5ed83045603b0ad204073fd788d0103a6c8"
		score = 75
		quality = 80
		tags = "GENERAL, WEBSHELLS"
		hash1 = "4935f0c50057e28efa7376c734a4c66018f8d20157b6584399146b6c79a6de15"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		memory_suitable = 1

	strings:
		$s1 = "Runtime.getRuntime().exec(request." ascii

	condition:
		$s1
}