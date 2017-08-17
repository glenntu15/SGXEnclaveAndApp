#include "enclave_test_save_t.h"
#include "sgx_tseal.h"
#include "sgx_trts.h"
#include <cstring>

char savedString[100] = "Default Enclave savedText";
char enclaveName[60] = "Original Save Enclave";
int savedInt = -1;
///////////////////////////
/////    edl file stuff
//trusted{
//	public sgx_status_t seal([in, size = plaintext_len]uint8_t* plaintext, size_t plaintext_len,[out, size = sealed_size]sgx_sealed_data_t* sealed_data, size_t sealed_size);
//
//public sgx_status_t unseal([in, size = sealed_size]sgx_sealed_data_t* sealed_data, size_t sealed_size,[out, size = plaintext_len]uint8_t* plaintext, uint32_t plaintext_len);
//};
//
/// end edl
/////////////////////////////////////////////

/**
* @brief      Seals the plaintext given into the sgx_sealed_data_t structure
*             given.
*
* @details    The plaintext can be any data. uint8_t is used to represent a
*             byte. The sealed size can be determined by computing
*             sizeof(sgx_sealed_data_t) + plaintext_len, since it is using
*             AES-GCM which preserves length of plaintext. The size needs to be
*             specified, otherwise SGX will assume the size to be just
*             sizeof(sgx_sealed_data_t), not taking into account the sealed
*             payload.
*
* @param      plaintext      The data to be sealed
* @param[in]  plaintext_len  The plaintext length
* @param      sealed_data    The pointer to the sealed data structure
* @param[in]  sealed_size    The size of the sealed data structure supplied
*
* @return     Truthy if seal successful, falsy otherwise.
*/
sgx_status_t enclaveSeal(uint8_t* plaintext, size_t plaintext_len, sgx_sealed_data_t* sealed_data, size_t sealed_size) {
	size_t sealed_size2 = sgx_calc_sealed_data_size(0, plaintext_len);
	sgx_status_t status = sgx_seal_data(0, NULL, plaintext_len, plaintext, sealed_size2, sealed_data);
	
	return status;
}
/**
* @brief      Unseal the sealed_data given into c-string
*
* @details    The resulting plaintext is of type uint8_t to represent a byte.
*             The sizes/length of pointers need to be specified, otherwise SGX
*             will assume a count of 1 for all pointers.
*
* @param      sealed_data        The sealed data
* @param[in]  sealed_size        The size of the sealed data
* @param      plaintext          A pointer to buffer to store the plaintext
* @param[in]  plaintext_max_len  The size of buffer prepared to store the
*                                plaintext
*
* @return     Truthy if unseal successful, falsy otherwise.
*/
sgx_status_t enclaveUnseal(sgx_sealed_data_t* sealed_data, size_t sealed_size, uint8_t* plaintext, uint32_t plaintext_len) {
	sgx_status_t status = sgx_unseal_data(sealed_data, NULL, NULL, (uint8_t*)plaintext, &plaintext_len);
	return status;
}
size_t getSealDataSize(int len)
{
	return sgx_calc_sealed_data_size(0, len);
}
// get enclave name
void getEnclaveName(char *output, size_t len) {
	if (len > strlen(enclaveName))
	{
		memcpy(output, enclaveName, strlen(enclaveName) + 1);
	}
	else 
	{
		memcpy(output, "false", strlen("false") + 1);
	}
}
// change a buffer with a constant string
void enclaveChangeBuffer(char *buf, size_t len)
{
	const char *secret = "Hello Enclave!";
	if (len > strlen(secret))
	{
		memcpy(buf, secret, strlen(secret) + 1);
	}
	else 
	{
		memcpy(buf, "false", strlen("false") + 1);
	}
}

// write a var to the buffer
void enclaveStringSave(char *input, size_t len) {
	if ((strlen(input) + 1) < 100)
	{
		memcpy(savedString, input, strlen(input) + 1);
	}
	else {
		memcpy(input, "false", strlen("false") + 1);
	}
}

// save the buffer to a var
void enclaveStringLoad(char *output, size_t len) {
	if (len > strlen(savedString))
	{
		memcpy(output, savedString, strlen(savedString) + 1);
	}
	else {
		memcpy(output, "false", strlen("false") + 1);
	}
}

// save a int to a var
void enclaveSaveInt(int input) {
	savedInt = input;
}

// return a var
int enclaveLoadInt() {
	return savedInt;
}