
rule VOLEXITY_Webshell_Aspx_Simpleseesharp : WEBSHELL UNCLASSIFIED FILE
{
	meta:
		description = "A simple ASPX Webshell that allows an attacker to write further files to disk."
		author = "threatintel@volexity.com"
		id = "469fdf5c-e09e-5d44-a2e6-0864dcd0e18a"
		date = "2021-03-01"
		modified = "2021-09-01"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2021/2021-03-02 - Operation Exchange Marauder/indicators/yara.yar#L1-L19"
		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
		hash = "893cd3583b49cb706b3e55ecb2ed0757b977a21f5c72e041392d1256f31166e2"
		logic_hash = "6f62249a68bae94e5cbdb4319ea5cde9dc071ec7a4760df3aafe78bc1e072c30"
		score = 75
		quality = 80
		tags = "WEBSHELL, UNCLASSIFIED, FILE"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$header = "<%@ Page Language=\"C#\" %>"
		$body = "<% HttpPostedFile thisFile = Request.Files[0];thisFile.SaveAs(Path.Combine"

	condition:
		$header at 0 and $body and filesize <1KB
}