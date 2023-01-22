#pragma once

#include<cstdint>

namespace pelib
{

struct
#if __has_cpp_attribute(__gnu__::__may_alias__)
[[__gnu__::__may_alias__]]
#endif
image_dos_header
{
::std::uint_least16_t magic_number;
::std::uint_least16_t cblp;
::std::uint_least16_t cp;
::std::uint_least16_t crlc;
::std::uint_least16_t cparhdr;
::std::uint_least16_t minalloc;
::std::uint_least16_t maxalloc;
::std::uint_least16_t ss;
::std::uint_least16_t sp;
::std::uint_least16_t csum;
::std::uint_least16_t ip;
::std::uint_least16_t cs;
::std::uint_least16_t lfarlc;
::std::uint_least16_t ovno;
::std::uint_least16_t res1[4];
::std::uint_least16_t oemid;
::std::uint_least16_t oeminfo;
::std::uint_least16_t res2[10];
::std::int_least32_t lfanew;
};
#if 0
enum class pe_machine_type: ::std::uint_least16_t
{
unknown=0,
target_host=1,
i386=0x14c,
r3000=0x162,
mips_le=0x162,
mips_be=0160,
r4000=0x166,
r10000=0x168,
};
#endif

struct
#if __has_cpp_attribute(__gnu__::__may_alias__)
[[__gnu__::__may_alias__]]
#endif
image_pe_header
{
::std::uint_least32_t mMagic; // PE\0\0 or 0x00004550
::std::uint_least16_t mMachine;
::std::uint_least16_t mNumberOfSections;
::std::uint_least32_t mTimeDateStamp;
::std::uint_least32_t mPointerToSymbolTable;
::std::uint_least32_t mNumberOfSymbols;
::std::uint_least16_t mSizeOfOptionalHeader;
::std::uint_least16_t mCharacteristics;
/*
Move part of optional part to base part
*/
::std::uint_least16_t mOptMagic; // 0x010b - PE32, 0x020b - PE32+ (64 bit)
::std::uint_least8_t  mMajorLinkerVersion;
::std::uint_least8_t  mMinorLinkerVersion;
::std::uint_least32_t mSizeOfCode;
::std::uint_least32_t mSizeOfInitializedData;
::std::uint_least32_t mSizeOfUninitializedData;
::std::uint_least32_t mAddressOfEntryPoint;
::std::uint_least32_t mBaseOfCode;
};
inline constexpr std::size_t image_numberof_directory_entries{16};

struct
#if __has_cpp_attribute(__gnu__::__may_alias__)
[[__gnu__::__may_alias__]]
#endif
image_data_directory
{
::std::uint_least32_t VirtualAddress;
::std::uint_least32_t Size;
};

struct
#if __has_cpp_attribute(__gnu__::__may_alias__)
[[__gnu__::__may_alias__]]
#endif
image_pe_optional_header_center
{
::std::uint_least32_t mSectionAlignment;
::std::uint_least32_t mFileAlignment;
::std::uint_least16_t mMajorOperatingSystemVersion;
::std::uint_least16_t mMinorOperatingSystemVersion;
::std::uint_least16_t mMajorImageVersion;
::std::uint_least16_t mMinorImageVersion;
::std::uint_least16_t mMajorSubsystemVersion;
::std::uint_least16_t mMinorSubsystemVersion;
::std::uint_least32_t mWin32VersionValue;
::std::uint_least32_t mSizeOfImage;
::std::uint_least32_t mSizeOfHeaders;
::std::uint_least32_t mCheckSum;
::std::uint_least16_t mSubsystem;
::std::uint_least16_t mDllCharacteristics;
};

struct
#if __has_cpp_attribute(__gnu__::__may_alias__)
[[__gnu__::__may_alias__]]
#endif
image_pe_optional_header_tail
{
::std::uint_least32_t mLoaderFlags;
::std::uint_least32_t mNumberOfRvaAndSizes;
image_data_directory DataDirectory[image_numberof_directory_entries];
inline constexpr std::span<image_data_directory> data_directories() noexcept
{
	return {DataDirectory,DataDirectory+mNumberOfRvaAndSizes};
}
};

struct
#if __has_cpp_attribute(__gnu__::__may_alias__)
[[__gnu__::__may_alias__]]
#endif
image_pe_optional_header32
{
::std::uint_least32_t mBaseOfData;
::std::uint_least32_t mImageBase;
image_pe_optional_header_center imageCenter;
::std::uint_least32_t mSizeOfStackReserve;
::std::uint_least32_t mSizeOfStackCommit;
::std::uint_least32_t mSizeOfHeapReserve;
::std::uint_least32_t mSizeOfHeapCommit;
image_pe_optional_header_tail imageTail;
};

struct
#if __has_cpp_attribute(__gnu__::__may_alias__)
[[__gnu__::__may_alias__]]
#endif
image_pe_optional_header64
{
::std::uint_least64_t mImageBase;
image_pe_optional_header_center imageCenter;
::std::uint_least64_t mSizeOfStackReserve;
::std::uint_least64_t mSizeOfStackCommit;
::std::uint_least64_t mSizeOfHeapReserve;
::std::uint_least64_t mSizeOfHeapCommit;
image_pe_optional_header_tail imageTail;
};

inline constexpr std::size_t image_sizeof_short_name{8};

struct
#if __has_cpp_attribute(__gnu__::__may_alias__)
[[__gnu__::__may_alias__]]
#endif
image_section_header
{
char Name[image_sizeof_short_name];
union
{
::std::uint_least32_t PhysicalAddress;
::std::uint_least32_t VirtualSize;
} Misc;
::std::uint_least32_t VirtualAddress;
::std::uint_least32_t SizeOfRawData;
::std::uint_least32_t PointerToRawData;
::std::uint_least32_t PointerToRelocations;
::std::uint_least32_t PointerToLinenumbers;
::std::uint_least16_t NumberOfRelocations;
::std::uint_least16_t NumberOfLinenumbers;
::std::uint_least32_t Characteristics;
};

struct
#if __has_cpp_attribute(__gnu__::__may_alias__)
[[__gnu__::__may_alias__]]
#endif
image_new_header
{
::std::uint_least16_t Reserved;
::std::uint_least16_t ResType;
::std::uint_least16_t ResCount;
};

struct
#if __has_cpp_attribute(__gnu__::__may_alias__)
[[__gnu__::__may_alias__]]
#endif
image_menu_header
{
::std::uint_least16_t wVersion;
::std::uint_least16_t cbHeaderSize;
};

struct
#if __has_cpp_attribute(__gnu__::__may_alias__)
[[__gnu__::__may_alias__]]
#endif
import_lookup_table_entry
{
	::std::uint_least32_t rva;
	::std::uint_least32_t timedata_stamp;
	::std::uint_least32_t forwarder_chain;
	::std::uint_least32_t name_rva;
	::std::uint_least32_t import_address_table_rva;
};

struct
#if __has_cpp_attribute(__gnu__::__may_alias__)
[[__gnu__::__may_alias__]]
#endif
image_import_by_name
{
	::std::uint_least16_t Hint;
	char Name[1];
}; 

struct
#if __has_cpp_attribute(__gnu__::__may_alias__)
[[__gnu__::__may_alias__]]
#endif
image_export_directory
{
	::std::uint_least32_t Characteristics;
	::std::uint_least32_t TimeDateStamp;
	::std::uint_least16_t MajorVersion;
	::std::uint_least16_t MinorVersion;
	::std::uint_least32_t Name;
	::std::uint_least32_t Base;
	::std::uint_least32_t NumberOfFunctions;
	::std::uint_least32_t NumberOfNames;
	::std::uint_least32_t AddressOfFunctions;
	::std::uint_least32_t AddressOfNames;
	::std::uint_least32_t AddressOfNameOrdinals;
};

struct
#if __has_cpp_attribute(__gnu__::__may_alias__)
[[__gnu__::__may_alias__]]
#endif
image_base_relocation
{
	struct relocation_offset
	{
//		::std::uint_least16_t value{};
		::std::uint_least16_t offs : 12;
		::std::uint_least16_t offtp : 4;
		constexpr ::std::uint_least8_t offtype() const noexcept
		{
//			constexpr ::std::uint_least8_t rshift{12u};
//			return static_cast<::std::uint_least8_t>(value>>rshift);
			return static_cast<::std::uint_least8_t>(offtp);
		}
		constexpr ::std::uint_least16_t offset() const noexcept
		{
//			constexpr ::std::uint_least16_t mask{(1<<12u)-1};
//			return value&mask;
			return offs;
		}
	};
	::std::uint_least32_t VirtualAdress;
	::std::uint_least32_t SizeOfBlock;
	relocation_offset offset[1];
};
struct
#if __has_cpp_attribute(__gnu__::__may_alias__)
[[__gnu__::__may_alias__]]
#endif
image_resource_directory_entry
{
struct resource_value
{
::std::uint_least32_t value:31;
::std::uint_least32_t highbit:1;
};
resource_value name_or_id;
resource_value offset_to_directory_or_to_data; 
};

struct
#if __has_cpp_attribute(__gnu__::__may_alias__)
[[__gnu__::__may_alias__]]
#endif
image_resource_dir_string_u
{
::std::uint_least16_t Length;
char16_t NameString[1];
};

struct
#if __has_cpp_attribute(__gnu__::__may_alias__)
[[__gnu__::__may_alias__]]
#endif
image_resource_data_entry
{
::std::uint_least32_t OffsetToData;
::std::uint_least32_t Size;
::std::uint_least32_t CodePage;
::std::uint_least32_t Reserved;
};

struct
#if __has_cpp_attribute(__gnu__::__may_alias__)
[[__gnu__::__may_alias__]]
#endif
image_resource_directory
{
::std::uint_least32_t characteristics;
::std::uint_least32_t timedatastamp;
::std::uint_least16_t majorversion;
::std::uint_least16_t minorversion;
::std::uint_least16_t number_of_named_entries;
::std::uint_least16_t number_of_id_entries;
image_resource_directory_entry DirectoryEntries[1];
inline constexpr std::span<image_resource_directory_entry> directory_entries() noexcept
{
	return std::span{DirectoryEntries,DirectoryEntries+(number_of_named_entries+number_of_id_entries)};
}
};

struct
#if __has_cpp_attribute(__gnu__::__may_alias__)
[[__gnu__::__may_alias__]]
#endif
image_runtime_function_entry
{
	::std::uint_least32_t BeginAddress;
	::std::uint_least32_t EndAddress;
	::std::uint_least32_t UnwindInfoAddressOrData;
};

struct image_pe_file_view
{
image_dos_header *dos_header{};
image_pe_header *pe_header{};
image_pe_optional_header32 *pe_optional_header32{};
image_pe_optional_header64 *pe_optional_header64{};
inline constexpr bool is_pe32() const noexcept
{
	return pe_optional_header32!=nullptr;
}
inline constexpr bool is_pe64() const noexcept
{
	return pe_optional_header64!=nullptr;
}
image_pe_optional_header_center *pe_optional_header_center{};
image_pe_optional_header_tail *pe_optional_header_tail{};
char* file_start{},*file_end{};
char* pe_start{};
image_section_header* section_headers_start{};

inline constexpr std::span<image_section_header> section_headers() noexcept
{
	return std::span<image_section_header>(this->section_headers_start,this->pe_header->mNumberOfSections);
}

inline ::std::uint_least32_t rva_to_offset(::std::uint_least32_t rva)
{
	auto secheaders{this->section_headers()};
	for(auto const& s : secheaders)
	{
		::std::uint_least32_t diff{rva-s.VirtualAddress};
		if(diff<s.SizeOfRawData)
		{
			return s.PointerToRawData+diff;
		}
	}
	::fast_io::throw_posix_error(EINVAL);
}

template<typename T>
#if __has_cpp_attribute(__gnu__::__may_alias__)
[[__gnu__::__may_alias__]]
#endif
inline T* rva_to_address(::std::uint_least32_t rva) noexcept(false)
{
	::std::uint_least32_t offs{rva_to_offset(rva)};
	::std::size_t file_size{static_cast<std::size_t>(file_end-file_start)};
	if(offs<file_size&&sizeof(T)<=file_size-offs)
#if __has_cpp_attribute(likely)
[[likely]]
#endif
	{
		return reinterpret_cast<T*>(this->file_start+offs);
	}
	::fast_io::throw_posix_error(EINVAL);
}

std::span<import_lookup_table_entry> import_lookup_table;
std::span<image_runtime_function_entry> image_runtime_function_table;
struct
{
	image_export_directory* export_directory{};
	::std::span<::std::uint_least32_t> functions;
	::std::span<::std::uint_least32_t> namervas;
	::std::span<::std::uint_least16_t> ordinals;
}export_info;

};

template<typename T>
inline T* extract_pointer(void* first,void *last)
{
	if(static_cast<std::size_t>(static_cast<char*>(last)-static_cast<char*>(first))<sizeof(T))
	{
		::fast_io::throw_posix_error(EINVAL);
	}
	return reinterpret_cast<T*>(first);
}

template<typename T>
inline T* extract_pointer_n(std::size_t n,void* first,void *last)
{
	constexpr std::size_t mx{std::numeric_limits<std::size_t>::max()/sizeof(T)};
	if(n>mx)
	{
		::fast_io::throw_posix_error(EINVAL);
	}
	std::size_t v{n*sizeof(T)};
	if(static_cast<std::size_t>(static_cast<char*>(last)-static_cast<char*>(first))<v)
	{
		::fast_io::throw_posix_error(EINVAL);
	}
	return reinterpret_cast<T*>(first);
}

inline image_pe_file_view parse_pe_file(void* first,void *last)
{
	image_pe_file_view pfv;
	pfv.file_start=reinterpret_cast<char*>(first);
	pfv.file_end=reinterpret_cast<char*>(last);
	char* firstptr{static_cast<char*>(first)};
	pfv.dos_header=extract_pointer<image_dos_header>(firstptr,last);
	if(pfv.dos_header->magic_number!=23117)
	{
		::fast_io::throw_posix_error(EINVAL);
	}
	char* pestart{firstptr+pfv.dos_header->lfanew};
	pfv.pe_header=extract_pointer<image_pe_header>(pestart,last);
	if(pfv.pe_header->mMagic!=0x00004550)
	{
		::fast_io::throw_posix_error(EINVAL);
	}
	pfv.pe_start=pestart;
	::std::uint_least16_t opt_magic{pfv.pe_header->mOptMagic};
	char* peoptionalstart{pestart+sizeof(image_pe_header)};
	auto* section_start{peoptionalstart};
	if(opt_magic==0x010b)	//PE32
	{
		pfv.pe_optional_header32=extract_pointer<image_pe_optional_header32>(peoptionalstart,last);
		pfv.pe_optional_header_center=__builtin_addressof(pfv.pe_optional_header32->imageCenter);
		pfv.pe_optional_header_tail=__builtin_addressof(pfv.pe_optional_header32->imageTail);
		section_start+=sizeof(image_pe_optional_header32);
	}
	else if(opt_magic==0x020b) //PE64
	{
		pfv.pe_optional_header64=extract_pointer<image_pe_optional_header64>(peoptionalstart,last);
		pfv.pe_optional_header_center=__builtin_addressof(pfv.pe_optional_header64->imageCenter);
		pfv.pe_optional_header_tail=__builtin_addressof(pfv.pe_optional_header64->imageTail);
		section_start+=sizeof(image_pe_optional_header64);
	}
	else
	{
		::fast_io::throw_posix_error(EINVAL);
	}
	pfv.section_headers_start=extract_pointer_n<image_section_header>(pfv.pe_header->mNumberOfSections,section_start,last);

	std::span DataDirectory{pfv.pe_optional_header_tail->DataDirectory};


	constexpr std::size_t image_directory_entry_export{};
	auto& export_info{pfv.export_info};
	::std::uint_least32_t export_vaddr{DataDirectory[image_directory_entry_export].VirtualAddress};
	if(export_vaddr)
	{
		auto& export_directory{*(export_info.export_directory=pfv.rva_to_address<image_export_directory>(export_vaddr))};
		export_info.functions=::std::span<::std::uint_least32_t>(pfv.rva_to_address<::std::uint_least32_t>(export_directory.AddressOfFunctions),export_directory.NumberOfFunctions);
		export_info.namervas=::std::span<::std::uint_least32_t>(pfv.rva_to_address<::std::uint_least32_t>(export_directory.AddressOfNames),export_directory.NumberOfNames);
		export_info.ordinals=::std::span<::std::uint_least16_t>(pfv.rva_to_address<::std::uint_least16_t>(export_directory.AddressOfNameOrdinals),export_directory.NumberOfNames);
	}
	return pfv;
}

}
