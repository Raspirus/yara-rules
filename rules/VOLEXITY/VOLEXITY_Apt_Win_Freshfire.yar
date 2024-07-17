rule VOLEXITY_Apt_Win_Freshfire : APT29
{
	meta:
		description = "The FRESHFIRE malware family. The malware acts as a downloader, pulling down an encrypted snippet of code from a remote source, executing it, and deleting it from the remote server."
		author = "threatintel@volexity.com"
		id = "050b8e61-139a-5ff5-998a-7de67c9975bf"
		date = "2021-05-27"
		modified = "2021-09-01"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2021/2021-05-27 - Suspected APT29 Operation Launches Election Fraud Themed Phishing Campaigns/indicators/yara.yar#L43-L67"
		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
		hash = "ad67aaa50fd60d02f1378b4155f69cffa9591eaeb80523489a2355512cc30e8c"
		logic_hash = "69cd73f5812ba955c1352fb1552774d5cf49019d6b65a304fd1e33f852e678ba"
		score = 75
		quality = 80
		tags = "APT29"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$uniq1 = "UlswcXJJWhtHIHrVqWJJ"
		$uniq2 = "gyibvmt\x00"
		$path1 = "root/time/%d/%s.json"
		$path2 = "C:\\dell.sdr"
		$path3 = "root/data/%d/%s.json"

	condition:
		(pe.number_of_exports==1 and pe.exports("WaitPrompt")) or any of ($uniq*) or 2 of ($path*)
}