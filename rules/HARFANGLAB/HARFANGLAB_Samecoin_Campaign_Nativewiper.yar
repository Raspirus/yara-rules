rule HARFANGLAB_Samecoin_Campaign_Nativewiper : FILE
{
	meta:
		description = "Matches the native Android library used in the SameCoin campaign"
		author = "HarfangLab"
		id = "9c77c26e-50f7-5ee4-bc6b-c0333e268b2c"
		date = "2024-02-13"
		modified = "2024-04-05"
		reference = "TRR240201"
		source_url = "https://github.com/HarfangLab/iocs/blob/911b0f27d123986b25ad00cc0e7d94a52435cb15/TRR240201/trr240201_yara.yar#L82-L102"
		license_url = "N/A"
		hash = "248054658277e6971eb0b29e2f44d7c3c8d7c5abc7eafd16a3df6c4ca555e817"
		logic_hash = "2779664830df3b5be72b7fe7d4da3d27e2a86b289ee3974596abf1df12317cd8"
		score = 75
		quality = 80
		tags = "FILE"
		context = "file"

	strings:
		$native_export = "Java_com_example_exampleone_MainActivity_deleteInCHunks" ascii
		$f1 = "_Z9chunkMainv" ascii
		$f2 = "_Z18deleteFilesInChunkRKNSt6__" ascii
		$f3 = "_Z18overwriteWithZerosPKc" ascii
		$s1 = "/storage/emulated/0/" ascii
		$s2 = "FileLister" ascii
		$s3 = "Directory chunks deleted."
		$s4 = "Current Chunk Size is:  %dl\n" ascii

	condition:
		filesize <500KB and uint32(0)==0x464C457F and ($native_export or all of ($f*) or all of ($s*))
}