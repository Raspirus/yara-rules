rule ESET_Mozi_Killswitch : FILE
{
	meta:
		description = "Mozi botnet kill switch"
		author = "Ivan Besina"
		id = "e3d34ae0-de06-5ff4-b44b-44d264b6dd29"
		date = "2023-09-29"
		modified = "2023-10-31"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/mozi/mozi.yar#L32-L51"
		license_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/LICENSE"
		logic_hash = "90eaed2f7f5595b145b2678a46ef6179082192215369fa9235024b0ce1574a49"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$iptables1 = "iptables -I INPUT  -p tcp --destination-port 7547 -j DROP"
		$iptables2 = "iptables -I OUTPUT -p tcp --sport 30005 -j DROP"
		$haha = "/haha"
		$networks = "/usr/networks"

	condition:
		all of them and filesize <500KB
}