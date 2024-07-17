rule SIGNATURE_BASE_WEBSHELL_PHP_In_Htaccess : FILE
{
	meta:
		description = "Use Apache .htaccess to execute php code inside .htaccess"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "0f5edff9-22b2-50c9-ae81-72698ea8e7db"
		date = "2021-01-07"
		modified = "2023-07-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_webshells.yar#L2748-L2770"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "c026d4512a32d93899d486c6f11d1e13b058a713"
		hash = "d79e9b13a32a9e9f3fa36aa1a4baf444bfd2599a"
		hash = "e1d1091fee6026829e037b2c70c228344955c263"
		hash = "c026d4512a32d93899d486c6f11d1e13b058a713"
		hash = "8c9e65cd3ef093cd9c5b418dc5116845aa6602bc92b9b5991b27344d8b3f7ef2"
		logic_hash = "0652a4cb0cb6c61afece5c2e4cbf2f281714509f0d828047f2e3ccd411602115"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		importance = 70

	strings:
		$hta = "AddType application/x-httpd-php .htaccess" wide ascii

	condition:
		filesize <100KB and $hta
}