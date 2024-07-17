
rule VOLEXITY_Apt_Webshell_Aspx_Glasstoken : UTA0178 FILE MEMORY
{
	meta:
		description = "Detection for a custom webshell seen on external facing server. The webshell contains two functions, the first is to act as a Tunnel, using code borrowed from reGeorg, the second is custom code to execute arbitrary .NET code."
		author = "threatintel@volexity.com"
		id = "5d96294c-aa61-5752-ab06-d5b27f6ac3a1"
		date = "2023-12-12"
		modified = "2024-01-09"
		reference = "TIB-20231215"
		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2024/2024-01-10 Ivanti Connect Secure/indicators/yara.yar#L24-L49"
		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
		logic_hash = "34844dc2ba4b18b25dcb5b14b7b80ec655595c9638600a0f2a6367610c542dd1"
		score = 75
		quality = 80
		tags = "UTA0178, FILE, MEMORY"
		hash1 = "26cbb54b1feb75fe008e36285334d747428f80aacdb57badf294e597f3e9430d"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 9994
		version = 5

	strings:
		$s1 = "=Convert.FromBase64String(System.Text.Encoding.Default.GetString(" ascii
		$re = /Assembly\.Load\(errors\)\.CreateInstance\("[a-z0-9A-Z]{4,12}"\).GetHashCode\(\);/

	condition:
		for any i in (0..#s1) : ($re in (@s1[i]..@s1[i]+512))
}