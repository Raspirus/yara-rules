rule ESET_Gazer_Logfile_Name : FILE
{
	meta:
		description = "Turla Gazer malware"
		author = "ESET Research"
		id = "3e1454e9-dddf-5197-b486-b96d725fdb58"
		date = "2017-08-30"
		modified = "2017-08-29"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/turla/gazer.yar#L67-L85"
		license_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/LICENSE"
		logic_hash = "b50553f4b4b07f124e5bd390e7dc8ac6b60a8ef185f3bc227894f957d6483478"
		score = 75
		quality = 80
		tags = "FILE"
		contact = "github@eset.com"
		license = "BSD 2-Clause"

	strings:
		$s1 = "CVRG72B5.tmp.cvr"
		$s2 = "CVRG1A6B.tmp.cvr"
		$s3 = "CVRG38D9.tmp.cvr"

	condition:
		( uint16(0)==0x5a4d) and 1 of them
}