/// App_test_save.cpp : Defines the entry point for the console application.
//
#include <string>
#include <stdio.h>
#include <tchar.h>
#include "sgx_urts.h"
#include "sgx_tseal.h"

//#define ENCLAVE_FILE _T("Enclave_test_save.signed.dll")
#define ENCLAVE_FILE _T("Enclave_test_save.signed.dll")
#define MAX_BUF_LEN 100

#include "sgx_urts.h"
#include "enclave_test_save_u.h"
//#include sgx_uae_service.h

int main()
{
	sgx_enclave_id_t   eid;
	sgx_status_t       ret = SGX_SUCCESS;
	sgx_launch_token_t token = { 0 };
	int updated = 0;
	char buffer[MAX_BUF_LEN] = "Hello World!";
	char secret[MAX_BUF_LEN] = "My secret string";
	char retSecret[MAX_BUF_LEN] = "";
	int secretIntValue = 0;
	int *secretIntPointer = &secretIntValue;
	int isdebug = SGX_DEBUG_FLAG;
	sgx_status_t status;
	printf("\nApp debug = %d\n", isdebug);

	//sgx_device_status_t *sgx_device_status;
	//satus = sgx_enable_device(sgx_device_status);


	status = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
	if (status == SGX_ERROR_INVALID_ENCLAVE)
	{
		printf("\nApp: error invalid enclave\n", status);
	}
	else if (status == SGX_ERROR_INVALID_PARAMETER)
	{
		printf("\nApp: error invalid parameter\n", status);
	}
	else if (status == SGX_ERROR_INVALID_METADATA)
	{
		printf("\nApp: error invalid metadata\n", status);
	}
	else if (status == SGX_ERROR_INVALID_VERSION)
	{
		printf("\nApp: error invalid version \n", status);
	}
	else if (status == SGX_ERROR_INVALID_SIGNATURE)
	{
		printf("\nApp: error invalid signature \n", status);
	}
	else if (status == SGX_ERROR_MEMORY_MAP_CONFLICT)
	{
		printf("\nApp: error memory map \n", status);
	}

	else if (status == SGX_ERROR_DEVICE_BUSY)
	{
		printf("\nApp: low level device is busy  \n", status);
	}

	else if (status == SGX_ERROR_SERVICE_UNAVAILABLE)
	{
		printf("\nApp: error AE service error \n", status);
	}
	else if (status == SGX_ERROR_SERVICE_TIMEOUT)
	{
		printf("\nApp: error AE service timeout error \n", status);
	}
	else if (status != SGX_SUCCESS) {
		printf("\nApp: error %#x, failed to create enclave.\n", status);
	}

	// A bunch of Enclave calls (ECALL) will happen here.

	// ...  seal test  ...
	char* pSealData = "This is data to be sealed";
	int len = strlen(pSealData) + 1;
	int sealint = 2017;
	int* ptr = &sealint;
	//len = sizeof(sealint);
	//int lenout = len + sizeof(sealData) + 1;
	//................................................
	printf("\nApp: Seal test:");
	//size_t sealed_size = sizeof(sgx_sealed_data_t) + len;
	size_t sealed_size;
	status = getSealDataSize(eid, &sealed_size, len);
	uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);

	sgx_status_t ecall_status;
	status = enclaveSeal(eid, &ecall_status,
		(uint8_t*)pSealData, len,
		(sgx_sealed_data_t*)sealed_data, sealed_size);
	printf("status %d\n", status);
	//...............................................
	FILE * pFile;
	pFile = fopen("sealeddata.txt", "wb");
	if (pFile != NULL) 
	{
		fwrite((const void *)&sealed_size, sizeof(sealed_size), 1, pFile);
		fwrite(sealed_data, sealed_size, 1, pFile);
	}
	fclose(pFile);

	pFile = fopen("sealeddata.txt", "rb");
	int insize;
	uint8_t* newsealed_data = 0;
	if (pFile != NULL)
	{
		fread(&insize, sizeof(insize), 1, pFile);
		newsealed_data = (uint8_t*)malloc(insize);
		fread(newsealed_data, insize, 1, pFile);
	}

	fclose(pFile);
	//...............................................
	printf("\nApp: Useal test:");
	//char * unsealed = new char[len+1];
	char* unsealed = new char[len + 1]; //int unsealed = 0;
	status = enclaveUnseal(eid, &ecall_status,
		(sgx_sealed_data_t*)newsealed_data, insize,
		(uint8_t*)unsealed, (uint32_t)len);
	int newlen = strlen(unsealed);
	for (int i = 0; i <= newlen; i++)
	{
		printf(" %c   %#1x \n", unsealed[i], unsealed[i]);
	}
	printf("status %d\n", status);
	//printf(" data = %s", us);
	//................................................

	
	//if (status == SGX_ERROR_INVALID_PARAMETER)
	//{
	//	printf(" SGX seal invalid parameter\n");
	//}

	printf("\nApp: Buffertests:\n");

	// Change the buffer in the enclave
	printf("App: Buffer before change: %s\n", buffer);
	enclaveChangeBuffer(eid, buffer, MAX_BUF_LEN);
	printf("App: Buffer after change: %s\n", buffer);


	printf("\nApp: Stringtests:\n");

	// Load a string from enclave
	// should return the default savedString from the enclave
	enclaveStringLoad(eid, retSecret, MAX_BUF_LEN);
	printf("App: Returned Secret: %s\n", retSecret);

	// Save a string in the enclave
	enclaveStringSave(eid, secret, strlen(secret) + 1);
	printf("App: Saved Secret: %s\n", secret);

	// Load a string from enclave
	// should return our secret string 
	enclaveStringLoad(eid, retSecret, MAX_BUF_LEN);
	printf("App: Load Secret: %s\n", retSecret);

	printf("\nApp: Integertests:\n");

	// Load integer from enclave
	// should return defauld savedInt from enclave
	enclaveLoadInt(eid, secretIntPointer);
	printf("App: secretIntValue first load: %d\n", secretIntValue);

	// Save integer to enclave
	enclaveSaveInt(eid, 1337);
	printf("App: saved a 1337 to the enclave. \n", 1337);

	// Load integer from enclave
	// should return our saved 1337
	enclaveLoadInt(eid, secretIntPointer);
	printf("App: secretIntValue second load after 1337 was saved: %d\n", secretIntValue);

	// Destroy the enclave when all Enclave calls finished.
	if (SGX_SUCCESS != sgx_destroy_enclave(eid))
		printf("\nApp: error, failed to destroy enclave.\n");

	getchar();
	return 0;
}
