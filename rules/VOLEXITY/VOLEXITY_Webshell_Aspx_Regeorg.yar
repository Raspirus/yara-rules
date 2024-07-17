
rule VOLEXITY_Webshell_Aspx_Regeorg : FILE MEMORY
{
	meta:
		description = "Detects the reGeorg webshell based on common strings in the webshell. May also detect other webshells which borrow code from ReGeorg."
		author = "threatintel@volexity.com"
		id = "02365a30-769e-5c47-8d36-a79608ffd121"
		date = "2018-08-29"
		modified = "2024-01-09"
		reference = "TIB-20231215"
		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2024/2024-01-10 Ivanti Connect Secure/indicators/yara.yar#L51-L83"
		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
		hash = "9d901f1a494ffa98d967ee6ee30a46402c12a807ce425d5f51252eb69941d988"
		logic_hash = "4fed023e85a32052917f6db1e2e155c91586538938c03acc59f200a8264888ca"
		score = 75
		quality = 80
		tags = "FILE, MEMORY"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 410
		version = 7

	strings:
		$a1 = "every office needs a tool like Georg" ascii
		$a2 = "cmd = Request.QueryString.Get(\"cmd\")" ascii
		$a3 = "exKak.Message" ascii
		$proxy1 = "if (rkey != \"Content-Length\" && rkey != \"Transfer-Encoding\")"
		$proxy_b1 = "StreamReader repBody = new StreamReader(response.GetResponseStream(), Encoding.GetEncoding(\"UTF-8\"));" ascii
		$proxy_b2 = "string rbody = repBody.ReadToEnd();" ascii
		$proxy_b3 = "Response.AddHeader(\"Content-Length\", rbody.Length.ToString());" ascii

	condition:
		any of ($a*) or $proxy1 or all of ($proxy_b*)
}