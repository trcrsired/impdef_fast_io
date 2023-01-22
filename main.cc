int main(int argc, char** argv)
{
	using namespace fast_io::mnp;
	if(argc<3)
	{
		if(argc == 0)
		{
			return 1;
		}
		perr("Usage: ",os_c_str(*argv)," <input dll> <output def>\n");
		return 1;
	}
	fast_io::native_file_loader loader(os_c_str(argv[1]));

	auto pfl{::pelib::parse_pe_file(loader.data(),loader.data()+loader.size())};
	fast_io::obuf_file obfraw(os_c_str(argv[2]));
	auto& obf{obfraw};
	std::string_view argv1(argv[1]);

	auto argv1last{argv1.crbegin()};
	for(;argv1last!=argv1.crend()&&(*argv1last!='\\'&&*argv1last!='/');++argv1last);

	auto partialstart{argv1last.base()};

	std::string_view filenm{partialstart,argv1.cend()};

	print(obf,"LIBRARY \"",filenm,"\"\nEXPORTS\n");
	if(pfl.export_info.export_directory)
	{
		for(auto nmrva : pfl.export_info.namervas)
		{
			println(obf,os_c_str(pfl.rva_to_address<char const>(nmrva)));
		}
	}
}