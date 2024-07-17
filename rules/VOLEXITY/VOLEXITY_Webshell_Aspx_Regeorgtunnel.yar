rule VOLEXITY_Webshell_Aspx_Regeorgtunnel : WEBSHELL COMMODITY
{
	meta:
		description = "variation on reGeorgtunnel"
		author = "threatintel@volexity.com"
		id = "b8aa27c9-a28a-5051-8f81-1184f28842ed"
		date = "2021-03-01"
		modified = "2021-09-01"
		reference = "https://github.com/sensepost/reGeorg/blob/master/tunnel.aspx"
		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2021/2021-03-02 - Operation Exchange Marauder/indicators/yara.yar#L21-L43"
		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
		hash = "406b680edc9a1bb0e2c7c451c56904857848b5f15570401450b73b232ff38928"
		logic_hash = "ea3d0532cb609682922469e8272dc8061efca3b3ae27df738ef2646e30404c6f"
		score = 75
		quality = 80
		tags = "WEBSHELL, COMMODITY"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$s1 = "System.Net.Sockets"
		$s2 = "System.Text.Encoding.Default.GetString(Convert.FromBase64String(StrTr(Request.Headers.Get"
		$t1 = ".Split('|')"
		$t2 = "Request.Headers.Get"
		$t3 = ".Substring("
		$t4 = "new Socket("
		$t5 = "IPAddress ip;"

	condition:
		all of ($s*) or all of ($t*)
}