rule VOLEXITY_Webshell_Aspx_Sportsball : WEBSHELL
{
	meta:
		description = "The SPORTSBALL webshell allows attackers to upload files or execute commands on the system."
		author = "threatintel@volexity.com"
		id = "d8cf1eb7-c08b-5c3c-b7d8-135b15418a7d"
		date = "2021-03-01"
		modified = "2021-09-01"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2021/2021-03-02 - Operation Exchange Marauder/indicators/yara.yar#L45-L68"
		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
		hash = "2fa06333188795110bba14a482020699a96f76fb1ceb80cbfa2df9d3008b5b0a"
		logic_hash = "4f90d727db91a93f53d08d2134f57bd03e7e2367aec3d78d275cfd192d7fb928"
		score = 75
		quality = 80
		tags = "WEBSHELL"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$uniq1 = "HttpCookie newcook = new HttpCookie(\"fqrspt\", HttpContext.Current.Request.Form"
		$uniq2 = "ZN2aDAB4rXsszEvCLrzgcvQ4oi5J1TuiRULlQbYwldE="
		$var1 = "Result.InnerText = string.Empty;"
		$var2 = "newcook.Expires = DateTime.Now.AddDays("
		$var3 = "System.Diagnostics.Process process = new System.Diagnostics.Process()"
		$var4 = "process.StandardInput.WriteLine(HttpContext.Current.Request.Form[\""
		$var5 = "else if (!string.IsNullOrEmpty(HttpContext.Current.Request.Form[\""
		$var6 = "<input type=\"submit\" value=\"Upload\" />"

	condition:
		any of ($uniq*) or all of ($var*)
}