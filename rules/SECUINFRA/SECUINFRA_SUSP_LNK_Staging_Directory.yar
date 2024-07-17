
rule SECUINFRA_SUSP_LNK_Staging_Directory : FILE
{
	meta:
		description = "Detects typical staging directories being referenced inside lnk files"
		author = "SECUINFRA Falcon Team"
		id = "459ed2e6-133c-5cde-bf49-95bf8a5eb8c8"
		date = "2022-02-27"
		modified = "2022-02-27"
		reference = "https://github.com/SIFalcon/Detection"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/Filetypes/lnk.yar#L31-L46"
		license_url = "N/A"
		logic_hash = "3f2a04702b39bce48fc85aa68f39e6062c3b5ee37667eb086222a866a5e438e4"
		score = 65
		quality = 70
		tags = "FILE"

	strings:
		$header = {4c00 0000 0114 0200 0000}
		$public = "$env:public" wide

	condition:
		filesize <20KB and ($header at 0) and $public
}