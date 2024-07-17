
rule VOLEXITY_Webshell_Php_Icescorpion : COMMODITY WEBSHELL FILE
{
	meta:
		description = "Detects the IceScorpion webshell."
		author = "threatintel@volexity.com"
		id = "dd165d67-375e-5d51-825a-45241345e268"
		date = "2022-01-17"
		modified = "2022-07-28"
		reference = "https://www.codenong.com/cs106064226/"
		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2022/2022-06-15 DriftingCloud - Zero-Day Sophos Firewall Exploitation and an Insidious Breach/indicators/yara.yar#L172-L190"
		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
		logic_hash = "0c75ec7cbbfdba8ce5f71a83d78caf19366954b84f304c1864e68bbe11a9a2df"
		score = 75
		quality = 80
		tags = "COMMODITY, WEBSHELL, FILE"
		hash1 = "5af4788d1a61009361b37e8db65deecbfea595ef99c3cf920d33d9165b794972"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		memory_suitable = 0

	strings:
		$s1 = "[$i+1&15];"
		$s2 = "openssl_decrypt"

	condition:
		all of them and filesize <10KB
}