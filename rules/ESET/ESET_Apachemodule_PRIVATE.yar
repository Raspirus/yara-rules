import "elf"

private rule ESET_Apachemodule_PRIVATE
{
	meta:
		description = "Apache 2.4 module ELF shared library"
		author = "ESET, spol. s r.o."
		id = "2082e50e-1726-5540-a962-e0aeca1ebaaf"
		date = "2024-04-27"
		modified = "2024-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/windigo/helimod.yar#L3-L30"
		license_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/LICENSE"
		hash = "e39667aa137e315bc26eaef791ccab52938fd809"
		logic_hash = "213fe381aa0bf9f148e488f7af74ac63073776c2868e42d2dcca7fdbca55fabb"
		score = 75
		quality = 80
		tags = ""
		license = "BSD 2-Clause"
		version = 1

	strings:
		$magic = "42PA"

	condition:
		for any s in elf.dynsym : (s.type==elf.STT_OBJECT and for any seg in elf.segments : (seg.type==elf.PT_LOAD and s.value>=seg.virtual_address and s.value<(seg.virtual_address+seg.file_size) and $magic at (s.value-seg.virtual_address+seg.offset)+0x28))
}