//============================================================================
// Author      : Andrew Art
// Version     : 1.0
// Copyright   : MIT License
//============================================================================

#include <boost/program_options.hpp>
namespace po = boost::program_options;

#include "fileSignaturer.h"


/**
 * @mainpage Signa
 *
 * @section intro_sec Description
 * Creates fingerprint of a file.
 *
 * @section syn_sec Command Syntax
 * Signa --input INPUTFILE --output OUTPUTFILE [ --block_size BS ] [ --verbose FLAG ]
 *
 * @section call_example Call Examples
 * Signa --input "input.file" --block_size "45" --output "output.file"
 * Signa -i "input.file" -bs "10" -o "output.file"
 * Signa --input "input.file" --output "output.file" --verbose true
 * Signa -h
 */
int main(int argc, char **argv) {
	try {
		po::options_description desc("Parameters' description");
		desc.add_options()
	    		 ("help,h", "show help")
				 ("input,i", po::value<string>(), "path to the input file")
				 ("output,o", po::value<string>(), "path to the output file")
		         ("block_size,bs", po::value<short>(),
		        		 "size of the input file's hashing unit (Mb, a natural number less than or equal to 1 Gb), default: 1 Mb")
				 ("verbose,v", po::value<bool>(), "output detailed information (default: false)");

		po::variables_map vm;
		po::store(po::parse_command_line(argc, argv, desc), vm);
		po::notify(vm);

		if (vm.count("help")) {
			cout << desc << endl;
			return 0;
		}

		if (vm.count("input")) {
			cout << "Input file path: "
					<< vm["input"].as<string>() << endl;
		} else {
			cerr << "Input file path not specified." << endl;
			return 1;
		}

		if (vm.count("output")) {
			cout << "Output file path: "
					<< vm["output"].as<string>() << endl;
		} else {
			cerr << "Output file path not specified." << endl;
			return 2;
		}

		unsigned short bs = 1;
		if (vm.count("block_size")) {
			if (vm["block_size"].as<short>() < 0) {
				cerr << "Block size cannot be negative." << endl;
				return 3;
			}
			bs = static_cast<unsigned short>(vm["block_size"].as<short>());
		}
		cout << "Block size = "	<< bs << " Mb" << endl;

		bool verbose = false;
		if (vm.count("verbose")) {
			if (vm["verbose"].as<bool>() == true) {
				verbose = vm["verbose"].as<bool>();
				cout << "Verbose = " << verbose << endl;
			}
		}

		fileSignaturer fsigner(vm["input"].as<string>(), bs);

		if (!fsigner.compute_signature(verbose))
			return 4;

		if (!fsigner.save_signature(vm["output"].as<string>()))
			return 5;
    }
	catch(exception& e) {
		cerr << "error: " << e.what() << endl;
		return 6;
	}
	catch(...) {
		cerr << "undetermined error" << endl;
	    return 7;
	}

	cout << "Done" << endl;
	return 0;
}
