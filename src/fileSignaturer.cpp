

#include "fileSignaturer.h"


fileSignaturer::fileSignaturer(const string& input, short bs) noexcept(false)
{
	///////////////////////////////////////////////////////////////////////////////////
	// Collect setup information (about target file and target system)
	///////////////////////////////////////////////////////////////////////////////////

	// Check chosen input file
	if ((!filesystem::exists(input)) || (filesystem::is_directory(input)))
		throw logic_error(std::string("File not found: ") + input);
	this->input_file = input;

	// Get input file's properties
	error_code ec;
	this->inputfile_size = filesystem::file_size(input_file, ec);
	if (ec)
		throw runtime_error("Estimating size of " + input_file + " error: " + ec.message());
	else
		sync_print("Input file size = " + to_string(inputfile_size) + " byte(s)", false);

	// Examine chosen block size
	if ((bs == 0) || (bs > 1024))
		throw logic_error(std::string("Incorrect block size"));
	this->block_size = bs << 20;

	// Quantity of blocks in input file. Equivalently,
	// quantity of hash values in output file
	const uintmax_t inputblocks_num = (inputfile_size > 0) ?
			static_cast<uintmax_t>(ceil(inputfile_size / static_cast<double>(block_size))) : 1;

	// RAM or Disk Space
	choose_cache_location(inputblocks_num);

	// Check quantity of CPUs
	uint cores_num = thread::hardware_concurrency();
	if ( (!cores_num) || (!inputfile_size))
		cores_num = 1;

	// Set quantity of work threads
	uintmax_t threads_num = (inputblocks_num > cores_num) ? cores_num : inputblocks_num;


	///////////////////////////////////////////////////////////////////////////////////
	// Prepare work threads, their caches and their inputfile's chunks characteristics
	///////////////////////////////////////////////////////////////////////////////////

	// Group inputfile's blocks to optimal chunks
	uintmax_t chunk_size_common = inputblocks_num / threads_num;
	uintmax_t chunk_size_remainder = inputblocks_num % threads_num;
	uintmax_t left_block = 0;
	uintmax_t right_block = 0;

	// Calculate chunks' details for every work thread
	struct chunk_settings
	{
		string hash_storage;
		uintmax_t left_boundary;
		uintmax_t right_boundary;
	};
	map<uint, chunk_settings> threadids_args;

	for (uint i = 0; i < threads_num; ++i) {
		string cache = "";
		if (cachestorage_available) {
			// Set unique name for work thread's exclusive cache file
			mt19937 generator{random_device{}()};
			uniform_int_distribution<int> discrete_uniform{'0', '9'};
			string rand_cachefilename(32, '\0');
			for( auto& elem : rand_cachefilename )
				elem = discrete_uniform(generator);
			cache = cache_dir + "/" + to_string(i) + "_" + rand_cachefilename + ".cache";
		}

		right_block = left_block + chunk_size_common + static_cast<bool>(chunk_size_remainder);

		threadids_args.emplace(i, chunk_settings{cache, left_block, right_block});

		left_block = right_block;
		if (chunk_size_remainder > 0)
			chunk_size_remainder--;
	}
	if (right_block != inputblocks_num)
		throw logic_error("Internal error: incorrect input file splitting");

	// Delay (suspend) computations of work threads while the leader thread is not fully ready
	auto lock = unique_lock<mutex>(chunkthreads_mutex);
	this->computations_complete = false;
	this->leaderthread_ready = false;

	// Assign chunks to work threads and start threads (in "suspended state")
	for ( const auto& thread_settings : threadids_args)
		caches_threads.emplace_back(pair<string, thread>
				(thread_settings.second.hash_storage, thread{[&]() {process_filechunk(thread_settings.first,
																					thread_settings.second.left_boundary,
																					thread_settings.second.right_boundary);}}));
}


void fileSignaturer::choose_cache_location(const uintmax_t& blocks_quant) noexcept(true)
{
	// environ => raw pointer without memory management
	const char * homedir;
	#ifdef __linux__
		homedir = getenv("HOME");
		if (homedir == nullptr) {
			homedir = getpwuid(getuid())->pw_dir;
		}
	#elif defined(_WIN32)
		homedir = getenv("USERPROFILE");
	#else
		homedir = nullptr;
	#endif

	if (homedir == nullptr) {
		#ifdef __linux__
			this->cache_dir = "/tmp";
			this->cachestorage_available = true;
		#else
			this->cache_dir = "";
			cachestorage_available = false;
		#endif
	} else {
		cache_dir = string(homedir);
		homedir = nullptr;
		cachestorage_available = true;
	}

	if (cachestorage_available) {
		// Evaluate storage free space
		const filesystem::space_info si = filesystem::space(cache_dir);
		// 64 - max length in bytes of a reasonably possible hash value (SHA512)
		if (si.available < static_cast<uintmax_t>(64 * blocks_quant))
			cachestorage_available = false;
		else {
			cache_dir += "/.cache/Signa";
			error_code ec;
			if (!filesystem::is_directory(cache_dir, ec)) {
				if ((ec) || (!filesystem::create_directories(cache_dir, ec))) {
					sync_print("Unable to create cache directory. " + ec.message(), true);
					cachestorage_available = false;
				}
			}
			if (cachestorage_available)
				sync_print("Cache will be stored in " + cache_dir + " directory", false);
		}
	}
}


void fileSignaturer::process_filechunk(const uint thread_id, const uintmax_t begin_block,
		                               const uintmax_t end_block) noexcept(true)
{
	// Wait for the leader thread
	auto lock = unique_lock<mutex>(chunkthreads_mutex);
	chunkthreads_notification.wait(lock, [this] { return leaderthread_ready; });
	lock.unlock();
	chunkthreads_notification.notify_all();

	if (stop_computations.load(memory_order_acquire))
		return;

	// Calculate boundary bytes
	uintmax_t start_pos = begin_block * block_size + thread_id;
	uintmax_t finish_pos = end_block * block_size + thread_id;
	sync_print(to_string(thread_id) + ": computations for " + input_file +
			   " from " + to_string(start_pos) + " byte to " +
			   to_string(finish_pos) + " byte in process", false);

	try {
		// Check thread's cache accessibility
		if ((cachestorage_available) && (filesystem::exists(caches_threads.at(thread_id).first)))
			throw runtime_error(caches_threads.at(thread_id).first +
					            " already exists. Unable to proceed");

		// Read thread's inputfile chunk block by block
		std::vector<char> plainblock(block_size,0);
		string cipherblock;
		ifstream if_input(input_file, ios_base::in | ios_base::binary);
		if_input.exceptions( ifstream::failbit | ifstream::badbit );
		if (!if_input.is_open())
			throw runtime_error(input_file + " error on open");

		for (uintmax_t i_block = begin_block; i_block < end_block; ++i_block) {
			if (stop_computations.load(memory_order_acquire)) {
				sync_print(to_string(thread_id) + ": computations for " + input_file +
						   " from " + to_string(start_pos) + " byte to " +
						   to_string(finish_pos) + " byte interrupted", true);
				return;
			}

			if (if_input.eof())
				throw logic_error(input_file + " error on read (unexpected eof)");

			if_input.seekg(i_block * block_size + thread_id);

			if ((thread_id == caches_threads.size() - 1) && (i_block == end_block - 1))
				if_input.exceptions( ifstream::goodbit );
			if_input.read(plainblock.data(), block_size);

			// Padding the very last block with zeros to the block size
			if (static_cast<uintmax_t>(if_input.gcount()) != block_size)
				fill(plainblock.begin() + if_input.gcount(),  plainblock.end(), 0);

			// Compute hash for current block using MD5 algorithm
			md5 boost_md5;
			boost_md5.process_bytes(plainblock.data(), block_size);
			md5::digest_type fingerprint;
			boost_md5.get_digest(fingerprint);
			const auto byte_fingerprint = reinterpret_cast<const char*>(&fingerprint);
			cipherblock.clear();
			hex(byte_fingerprint, byte_fingerprint+sizeof(md5::digest_type), back_inserter(cipherblock));

			// Save block's hash value into cache
			if (cachestorage_available) {
				ofstream cachefile;
				cachefile.exceptions( ifstream::failbit | ifstream::badbit );
				cachefile.open(caches_threads.at(thread_id).first, ios_base::app);
				if (!cachefile.is_open())
					throw runtime_error(caches_threads.at(thread_id).first + " error on open");
				cachefile << cipherblock;
				cachefile.close();
			}
			else {
				caches_threads.at(thread_id).first.append(cipherblock);
			}

			if (verbose_mode)
				sync_print("Hash for block " + to_string(i_block) +
						   " calculated and stored in cache", false);
		}
		if_input.close();
	}
	catch (exception& e) {
		sync_print("Error during " + input_file +
				   " signature computations: " + string(e.what()), true);
		stop_computations.store(true, memory_order_release);
		return;
	}

	sync_print(to_string(thread_id) + ": computations for " + input_file +
			   " from " + to_string(start_pos) + " byte to " +
			   to_string(finish_pos) + " byte completed", false);

}


void fileSignaturer::wait_for_workers() noexcept(true)
{
	if (!caches_threads.size())
		return;

	for ( auto& cachethread : caches_threads )
	{
		if (cachethread.second.joinable())
			cachethread.second.join();
	}
}


bool fileSignaturer::compute_signature(bool verbose) noexcept(true)
{
	this->verbose_mode = verbose;

	if (!computations_complete) {
		sync_print("Signature computations in progress...", false);

		// Leader is ready, unsuspends work threads
		release_workers(false, true);
		wait_for_workers();

		if (stop_computations.load(memory_order_acquire)) {
			sync_print("Signature computations failed", true);
			return false;
		} else
			computations_complete = true;
	} else if (verbose_mode)
		sync_print("Signature has been already calculated", false);

	sync_print("Signature computations has been completed", false);

	return true;
}


bool fileSignaturer::assemble_output(const string& output_file) const noexcept(true)
{
	bool ret_val = true;

	try {
		if (caches_threads.size() > 0) {
			error_code ec;
			filesystem::remove(output_file, ec);
			if (ec)
				throw runtime_error(output_file +
						" unsuccessful overwrite attempt of an existing file: " + ec.message());
			ofstream of_whole;
			of_whole.exceptions(ofstream::badbit | ofstream::failbit);
			if (cachestorage_available) {
				// Assemble cache files
				of_whole.open(output_file, ios_base::out | ios_base::binary | ios_base::app);
				if (!of_whole.is_open())
					throw runtime_error(output_file + " error on open");
				for ( const auto& cachethread : caches_threads ) {
					ifstream if_chunk(cachethread.first, ios_base::in | ios_base::binary);
					if_chunk.exceptions(ofstream::badbit | ofstream::failbit);
					if (!if_chunk.is_open())
							throw runtime_error(cachethread.first + " error on open");
					of_whole.seekp(0, ios_base::end);
					of_whole << if_chunk.rdbuf();
					if_chunk.close();
				}
			} else {
				// Assemble RAM-based caches
				of_whole.open(output_file, ios_base::out | ios_base::app);
				if (!of_whole.is_open())
					throw runtime_error(output_file + " error on open");
				for ( const auto& cachethread : caches_threads )
					of_whole << cachethread.first;
			}
			of_whole.close();
		} else
			throw logic_error(string("Empty cache, nothing to assemble"));
	}
	catch(exception& e) {
		sync_print("Assembling error: " + string(e.what()), true);
		ret_val = false;
	}

	return ret_val;
}


bool fileSignaturer::save_signature(const string& output) const noexcept(true)
{
	if (stop_computations.load(memory_order_acquire)) {
		sync_print("Nothing to save. Calculation errors has been found", true);
		return false;
	}

	if (!computations_complete) {
		sync_print("Calculations in progress, please wait", true);
		return false;
	}

	sync_print("Signature saving...", false);

	error_code ec;
	if (filesystem::is_directory(output, ec)) {
		if (ec)
			sync_print(output + " location examining error: " + ec.message(), true);
		else
			sync_print(output + " is an existing directory", true);
		return false;
	}

	if (assemble_output(output)) {
		sync_print("Signature has been saved", false);
		return true;
	}

	sync_print(string("Errors during signature saving"), false);
	return false;
}


bool fileSignaturer::clear_cache() noexcept(true)
{
	bool ret_val = true;
	error_code ec;

	if (caches_threads.size() > 0) {

		if ((!stop_computations.load(memory_order_acquire)) && (!computations_complete))
			release_workers(true, false);

		wait_for_workers();

		for ( auto& cachethread : caches_threads ) {
			if (cachestorage_available) {
				if (filesystem::exists(cachethread.first, ec)) {
					filesystem::remove(cachethread.first, ec);
					if (ec) {
						sync_print("Cache clearing error: " + ec.message() +
								   " at file " + cachethread.first, true);
						ret_val = false;
					}
				} else {
					sync_print("Missing cache file: " + cachethread.first, true);
					ret_val = false;
				}
			} else {
				cachethread.first = "";
			}
		}

		caches_threads.clear();

		if (ret_val)
			sync_print("Cache successfully cleared", false);

	} else {
		sync_print("Cache is already empty", false);
	}

	return ret_val;
}


void fileSignaturer::release_workers(const bool abort, const bool init) noexcept(true)
{
	if (computations_complete)
		return;

	if (init)
		stop_computations.store(!init, memory_order_release);
	if (abort)
		stop_computations.store(abort, memory_order_release);
	leaderthread_ready = true;
	auto lock = unique_lock<mutex>(chunkthreads_mutex);
	lock.unlock();
	chunkthreads_notification.notify_all();
}


void fileSignaturer::sync_print(const string& str, bool is_errmsg) const noexcept(true)
{
	print_mutex.lock();
	if (is_errmsg)
		cerr << str << endl;
	else
		cout << str << endl;
	print_mutex.unlock();
}


fileSignaturer::~fileSignaturer()
{
	try {
		if (!clear_cache())
			sync_print("Errors during clearing the cache", true);
	}
	catch (...)
	{
		sync_print("fileSignaturer: exception in destructor!", true);
	}
}
