import "elf"


import "pe"


import "elf"


import "elf"


import "elf"


import "elf"


import "elf"


import "pe"


import "pe"


import "pe"


import "pe"


import "pe"


import "pe"


import "pe"


import "pe"


import "pe"


import "pe"


import "pe"


import "pe"


import "pe"


import "pe"


rule ESET_Gazer_Certificate : FILE
{
	meta:
		description = "Turla Gazer malware"
		author = "ESET Research"
		id = "e90bbe53-4e7f-59c4-a505-4893150bf824"
		date = "2017-08-30"
		modified = "2017-08-29"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/turla/gazer.yar#L48-L65"
		license_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/LICENSE"
		logic_hash = "eb3afbaefd23d4fc6ded494d3378dc910a0832b160e733ab79c590128dd74cea"
		score = 75
		quality = 80
		tags = "FILE"
		contact = "github@eset.com"
		license = "BSD 2-Clause"

	strings:
		$certif1 = {52 76 a4 53 cd 70 9c 18 da 65 15 7e 5f 1f de 02}
		$certif2 = {12 90 f2 41 d9 b2 80 af 77 fc da 12 c6 b4 96 9c}

	condition:
		( uint16(0)==0x5a4d) and 1 of them and filesize <2MB
}