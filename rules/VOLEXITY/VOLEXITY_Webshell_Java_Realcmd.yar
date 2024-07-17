
rule VOLEXITY_Webshell_Java_Realcmd : COMMODITY WEBSHELLS
{
	meta:
		description = "Detects the RealCMD webshell, one of the payloads for BEHINDER."
		author = "threatintel@volexity.com"
		id = "d5e7e3c8-a0aa-5c2e-8a2d-654e066593eb"
		date = "2022-06-01"
		modified = "2022-06-06"
		reference = "https://github.com/Freakboy/Behinder/blob/master/src/main/java/vip/youwe/sheller/payload/java/RealCMD.java"
		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2022/2022-06-02 Active Exploitation Of Confluence 0-day/indicators/yara.yar#L52-L79"
		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
		logic_hash = "244add844570b23e5df23882a3fdacf894f3e201b01373d949b0752361960536"
		score = 75
		quality = 80
		tags = "COMMODITY, WEBSHELLS"
		hash1 = "a9a30455d6f3a0a8cd0274ae954aa41674b6fd52877fafc84a9cb833fd8858f6"
		memory_suitable = 1
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$fn1 = "runCmd" wide ascii fullword
		$fn2 = "RealCMD" ascii wide fullword
		$fn3 = "buildJson" ascii wide fullword
		$fn4 = "Encrypt" ascii wide fullword
		$s1 = "AES/ECB/PKCS5Padding" ascii wide
		$s2 = "python -c 'import pty; pty.spawn" ascii wide
		$s3 = "status" ascii wide
		$s4 = "success" ascii wide
		$s5 = "sun.jnu.encoding" ascii wide
		$s6 = "java.util.Base64" ascii wide

	condition:
		all of ($fn*) or all of ($s*)
}