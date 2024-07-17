import "pe"


rule ESET_Apt_Windows_Invisimole_CPL_Loader : FILE
{
	meta:
		description = "CPL loader"
		author = "ESET Research"
		id = "feff8627-6085-5835-ac1b-d4522245f7db"
		date = "2021-05-17"
		modified = "2021-05-17"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/invisimole/invisimole.yar#L97-L118"
		license_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/LICENSE"
		logic_hash = "cd5c19e14faa7fd3758b30193ccf2bed3692ad29d8216466523ca25d2abcfe88"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "WScr%steObject(\"WScr%s.Run(\"::{20d04fe0-3a%s30309d}\\\\::{21EC%sDD-08002B3030%s\", 0);"
		$s2 = "\\Control.js" wide
		$s3 = "\\Control Panel.lnk" wide
		$s4 = "FPC 3.0.4 [2019/04/13] for x86_64 - Win64"
		$s5 = "FPC 3.0.4 [2019/04/13] for i386 - Win32"
		$s6 = "imageapplet.dat" wide
		$s7 = "wkssvmtx"

	condition:
		uint16(0)==0x5A4D and (3 of them )
}