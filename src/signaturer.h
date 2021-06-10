
#ifndef SIGNATURER_H_
#define SIGNATURER_H_

#include <string>


/**
 * @class signaturer
 * @brief Fingerprint class interface.
 * Possible derived classes: fileSignaturer, dirSignaturer,
 * textSignaturer, memSignaturer, websiteSignaturer, etc
 */
class signaturer
{
public:
	/**
	 * @brief Calculates collision-resistant fingerprint of a target data.
	 * @param verbose Level of additional information provided to the user
	 * @value true Extendent information during calculations is needed
	 * @value false Only obligatory brief information
	 * @return status
	 * @value true success
	 * @value false fail
	 */
	virtual bool compute_signature(bool verbose) = 0;

	/**
	 * @brief Saves calculated fingerprint to provided \a output location.
	 * @param output Location of the calculated fingerprint
	 * @return status
	 * @value true success
	 * @value false fail
	 *
	 * @see compute_signature()
	 */
	virtual bool save_signature(const string& output) const = 0;

	/**
	 * @brief Destructor of the signaturer base class.
	 */
	virtual ~signaturer() = default;
};


#endif /* SIGNATURER_H_ */
