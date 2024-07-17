rule ESET_Apt_Windows_Invisimole_C2 : FILE
{
	meta:
		description = "InvisiMole C&C servers"
		author = "ESET Research"
		id = "9279c8cd-2c16-5f90-a7f5-e668d57c805b"
		date = "2021-05-17"
		modified = "2021-05-17"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/invisimole/invisimole.yar#L257-L297"
		license_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/LICENSE"
		logic_hash = "aff8456ce7a9ebe875c02e51c09b77ee7b1fddfc11d4ad236e12c8c5240a01a8"
		score = 75
		quality = 78
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "46.165.220.228" ascii wide
		$s2 = "80.255.3.66" ascii wide
		$s3 = "85.17.26.174" ascii wide
		$s4 = "185.193.38.55" ascii wide
		$s5 = "194.187.249.157" ascii wide
		$s6 = "195.154.255.211" ascii wide
		$s7 = "153.re" ascii wide fullword
		$s8 = "adstat.red" ascii wide
		$s9 = "adtrax.net" ascii wide
		$s10 = "akamai.sytes.net" ascii wide
		$s11 = "amz-eu401.com" ascii wide
		$s12 = "blabla234342.sytes.net" ascii wide
		$s13 = "mx1.be" ascii wide fullword
		$s14 = "statad.de" ascii wide
		$s15 = "time.servehttp.com" ascii wide
		$s16 = "upd.re" ascii wide fullword
		$s17 = "update.xn--6frz82g" ascii wide
		$s18 = "updatecloud.sytes.net" ascii wide
		$s19 = "updchecking.sytes.net" ascii wide
		$s20 = "wlsts.net" ascii wide
		$s21 = "ro2.host" ascii wide fullword
		$s22 = "2ld.xyz" ascii wide fullword
		$s23 = "the-haba.com" ascii wide
		$s24 = "82.202.172.134" ascii wide
		$s25 = "update.xn--6frz82g" ascii wide

	condition:
		(( uint16(0)==0x5A4D) or ESET_Invisimole_Blob_PRIVATE) and $s21 and any of them
}