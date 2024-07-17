rule VOLEXITY_General_Java_Encoding_And_Classloader : WEBSHELLS GENERAL FILE
{
	meta:
		description = "Identifies suspicious java-based files which have all the ingredients required for a webshell."
		author = "threatintel@volexity.com"
		id = "7de5449d-de70-5153-b1b1-8a995ac8b7a0"
		date = "2022-04-07"
		modified = "2022-07-28"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2022/2022-06-15 DriftingCloud - Zero-Day Sophos Firewall Exploitation and an Insidious Breach/indicators/yara.yar#L25-L43"
		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
		logic_hash = "21c226b03451eb98a8be5b26a9f00169f16454ecd21d4131c9991b63d2e3c8cd"
		score = 65
		quality = 80
		tags = "WEBSHELLS, GENERAL, FILE"
		hash1 = "0d5dc54ef77bc18c4c5582dca4619905605668cffcccc3829e43c6d3e14ef216"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		memory_suitable = 0

	strings:
		$s1 = "javax.crypto.spec.SecretKeySpec" ascii
		$s2 = "java/security/SecureClassLoader" ascii
		$s3 = "sun.misc.BASE64Decoder" ascii

	condition:
		filesize <50KB and all of them
}