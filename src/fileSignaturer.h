
#ifndef FILESIGNATURER_H_
#define FILESIGNATURER_H_

#include <iostream>
#include <fstream>
#include <filesystem>
#include <thread>
#include <random>
#include <condition_variable>
#if defined(__linux__)
	#include <pwd.h>
#endif
#include <boost/algorithm/hex.hpp>
#include <boost/uuid/detail/md5.hpp>
using boost::algorithm::hex;
using boost::uuids::detail::md5;
using namespace std;

#include "signaturer.h"


/**
 * @class fileSignaturer
 * @brief Computes fingerprint (cumulative hash for every file's data block)
 * of a specified input file.
 * Saves input file's cumulative hash into specified output file.
 */
class fileSignaturer : public signaturer
{
protected:

	/**
	 * @brief Valid path to user provided input file.
	 */
	string input_file;

	/**
	* @brief Size of the input file (in bytes).
	* @see input_file
	*/
	uintmax_t inputfile_size;

	/**
	 * @brief Given size of the input file's hashing unit,
	 * transformed from Mb to bytes.
	 */
	uintmax_t block_size;

	/**
	 * @brief Flag of disk (user's home storage) accessibility for
	 * temporary cache usage in order to reduce RAM consumption.
	 */
	bool cachestorage_available;

	/**
	 * @brief Directory in user's home storage for temporary hash data chunks.
	 */
	string cache_dir;

	/**
	 * @brief Each entry is a pair of working thread's cache and
	 * a thread's descriptor. Thread index in the vector is the thread's ID.
	 * THe size of this data structure is a) the quantity of hashes in the output
	 * file and b) the number of cores that'll be heavily used throughout the
	 * active phase of the input file's fingerprint calculating.
	 */
	vector<pair<string, thread>> caches_threads;

	/**
	 * @brief Guard of working threads suspending by leader thread.
	 */
	mutex chunkthreads_mutex;

	/**
	 * @brief Notifiable flag, part of working threads suspending mechanism.
	 * @see chunkthreads_mutex, chunkthreads_notification
	 */
	bool leaderthread_ready;

	/**
	 * @brief Notification (from leader to working threads),
	 * part of working threads suspending mechanism.
	 * @see chunkthreads_mutex, leaderthread_ready
	 */
	condition_variable chunkthreads_notification;

	/**
	 * @brief Flag of successfully ending of the fingerprint computing.
	 * The flag is raised by the lead thread when all computational
	 * jobs are done and cache is fully available for assembling.
	 *
	 * @see compute_signature()
	 */
	bool computations_complete;

	/**
	 * @brief Flag of unsuccessfully ending of the fingerprint computing.
	 * The flag can be raised by one of the worker threads,
	 * which interrupts all of the computations or in case of an emergency
	 * calculations shutdown by the leader thread.
	 *
	 * @see release_workers()
	 */
	atomic<bool> stop_computations;

	/**
	* @brief Given level of additional information provided to user during
	* active phase of fingerprint computations.
	*/
	bool verbose_mode;

	/**
	 * @brief Determines and sets an optimal cache location based on
	 * \a blocks_quant.
	 * @param blocks_quant The minimum number of blocks in which the input file is fit into
	 * @exceptsafe Shall not throw exceptions.
	 *
	 * @see cachestorage_available, cache_dir
	 */
	virtual void choose_cache_location(const uintmax_t& blocks_quant) noexcept(true);

	/**
	 * @brief Starts/stops working threads.
	 * @param abort Interrupt all computations
	 * @param init Allow start of all computations
	 * @exceptsafe Shall not throw exceptions.
	 *
	 * @see compute_signature(), clear_cache()
	 */
	virtual void release_workers(const bool abort, const bool init) noexcept(true);

	/**
	 * @brief Hangs untill working threads make their job done.
	 * @exceptsafe Shall not throw exceptions.
	 *
	 * @see compute_signature(), clear_cache(), caches_threads
	 */
	virtual void wait_for_workers() noexcept(true);

	/**
	 * @brief Reads specified blocks' range of the input file,
	 * compute blocks' MD5 hash values and store these values into cache.
	 * Working thread method.
	 *
	 * @param thread_id Thread's identifier
	 * @param begin_block First block to proceed
	 * @param end_block Last block to proceed
	 * @exceptsafe Shall not throw exceptions.
	 */
	virtual void process_filechunk(const uint thread_id,
									const uintmax_t begin_block, const uintmax_t end_block) noexcept(true);

	/**
	 * @brief Gathers temporary cached chunks of the computed signature into the one
	 * result \a output file.
	 * @param output Path to the output result file
	 * @return status
	 * @value true success
	 * @value false fail
	 * @exceptsafe Shall not throw exceptions.
	 *
	 * @see save_signature(), caches_threads
	 */
	virtual bool assemble_output(const string& output) const noexcept(true);

	/**
	 * @brief Cleans temporary cached hash data, stops and "flush" working threads
	 * if they not completed their jobs.
	 * @return status
	 * @value true success
	 * @value false fail
	 * @exceptsafe Shall not throw exceptions.
	 *
	 * @see caches_threads
	 */
	virtual bool clear_cache() noexcept(true);

	/**
	 * @brief Guard of console printing which shared by the leader and working threads.
	 * @see sync_print()
	 */
	mutable mutex print_mutex;

	/**
	 * @brief Synchronized console printing method
	 * for leader thread and working threads.
	 * @param str Message for console printing
	 * @param is_errmsg Message error status
	 * @value true Error (standard error stream)
	 * @value false Normal (standard output stream)
	 * @exceptsafe Shall not throw exceptions.
	 *
	 * @see print_mutex
	 */
	virtual void sync_print(const string& str, bool is_errmsg) const noexcept(true);

public:

	/**
	* @brief Creates instance of the fileSignaturer class.
	* Provides fingerprint calculations' preparations:
	* gathers system info (cores quantity, available storage size),
	* determines an optimal cache location, calculates chunks' sizes
	* based on the \a input file size and the * \a bs (block size),
	* starts working threads in a suspended state.
	* @param input Path to the input source file
	* @param bs Block size (in Mb, up to 1Gb, default: 1)
	* @throws logic_error Input file not found, internal errors
	* @throws runtime_error File system access errors
	* @exceptsafe strong
	*
	* @see choose_cache_location()
	*/
	fileSignaturer(const string& input, short bs) noexcept(false);

	/**
	 * @brief Calculates signature (fingerprint) for object's input file
	 * using multithreading. Lead thread delegates all fingerprint calculations
	 * to working threads, the lead thread's actions are to unsuspend
	 * working threads and waiting results from them.
	 * Leader thread method.
	 * @param verbose Level of additional information provided to the user
	 * @value true Extendent information during calculations is required
	 * (Potentially slows down computations)
	 * @value false Provide only obligatory brief information
	 * @return status
	 * @value true success
	 * @value false fail
	 * @exceptsafe Shall not throw exceptions.
	 *
	 * @see release_workers(), process_filechunk(), wait_for_workers()
	 */
	bool compute_signature(bool verbose) noexcept(true);

	/**
	 * @brief Saves calculated input file's fingerprint to provided \a output file.
	 * @param output - path to the output result file
	 * @exceptsafe Shall not throw exceptions.
	 *
	 * @see assemble_output()
	 */
	bool save_signature(const string& output) const noexcept(true);

	/**
	 * @brief Cleans working threads' caches and stops these threads
	 * if needed.
	 * @exceptsafe Shall not throw exceptions.
	 *
	 * @see clear_cache()
	 */
	~fileSignaturer();
};


#endif /* FILESIGNATURER_H_ */
