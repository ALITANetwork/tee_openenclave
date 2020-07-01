// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <errno.h>
#include <openenclave/host_verify.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

size_t get_filesize(FILE* fp)
{
    size_t size = 0;
    fseek(fp, 0, SEEK_END);
    size = (size_t)ftell(fp);
    fseek(fp, 0, SEEK_SET);

    return size;
}

bool read_binary_file(
    const char* filename,
    uint8_t** data_ptr,
    size_t* size_ptr)
{
    size_t size = 0;
    uint8_t* data = NULL;
    size_t bytes_read = 0;
    bool result = false;
    FILE* fp = NULL;
#ifdef _WIN32
    if (fopen_s(&fp, filename, "rb") != 0)
#else
    if (!(fp = fopen(filename, "rb")))
#endif
    {
        fprintf(stderr, "Failed to open: %s\n", filename);
        goto exit;
    }

    *data_ptr = NULL;
    *size_ptr = 0;

    // Find file size
    size = get_filesize(fp);
    if (size == 0)
    {
        fprintf(stderr, "Empty file: %s\n", filename);
        goto exit;
    }

    data = (uint8_t*)malloc(size);
    if (data == NULL)
    {
        fprintf(
            stderr,
            "Failed to allocate memory of size %lu\n",
            (unsigned long)size);
        goto exit;
    }

    bytes_read = fread(data, sizeof(uint8_t), size, fp);
    if (bytes_read != size)
    {
        fprintf(stderr, "Failed to read file: %s\n", filename);
        goto exit;
    }

    result = true;

exit:
    if (fp)
    {
        fclose(fp);
    }

    if (!result)
    {
        if (data != NULL)
        {
            free(data);
            data = NULL;
        }
        bytes_read = 0;
    }

    *data_ptr = data;
    *size_ptr = bytes_read;

    return result;
}

oe_result_t verify_report(
    const char* report_filename,
    const char* endorsement_filename)
{
    oe_result_t result = OE_FAILURE;
    size_t report_file_size = 0;
    uint8_t* report_data = NULL;
    size_t endorsement_file_size = 0;
    uint8_t* endorsement_data = NULL;

    if (read_binary_file(report_filename, &report_data, &report_file_size))
    {
        if (endorsement_filename != NULL)
        {
            read_binary_file(
                endorsement_filename,
                &endorsement_data,
                &endorsement_file_size);
        }

        result = oe_verify_remote_report(
            report_data,
            report_file_size,
            endorsement_data,
            endorsement_file_size,
            NULL);
    }

    if (report_data != NULL)
    {
        free(report_data);
    }

    if (endorsement_data != NULL)
    {
        free(endorsement_data);
    }

    return result;
}

oe_result_t enclave_identity_verifier(oe_identity_t* identity, void* arg)
{
    (void)arg;

    printf(
        "Enclave certificate contains the following identity information:\n");
    printf("identity.security_version = %d\n", identity->security_version);

    printf("identity->unique_id:\n0x ");
    for (int i = 0; i < 32; i++)
        printf("%0x ", (uint8_t)identity->unique_id[i]);

    printf("\nidentity->signer_id:\n0x ");
    for (int i = 0; i < 32; i++)
        printf("%0x ", (uint8_t)identity->signer_id[i]);

    printf("\nidentity->product_id:\n0x ");
    for (int i = 0; i < 16; i++)
        printf("%0x ", (uint8_t)identity->product_id[i]);

    return OE_OK;
}

oe_result_t verify_cert(const char* filename)
{
    oe_result_t result = OE_FAILURE;
    size_t cert_file_size = 0;
    uint8_t* cert_data = NULL;

    if (read_binary_file(filename, &cert_data, &cert_file_size))
    {
        result = oe_verify_attestation_certificate(
            cert_data, cert_file_size, enclave_identity_verifier, NULL);
    }

    if (cert_data != NULL)
    {
        free(cert_data);
    }

    return result;
}

void print_syntax(const char* program_name)
{
    fprintf(
        stdout,
        "Usage:\n  %s -r <report_file> [-e <endorsement_file>]\n  %s -c "
        "<certificate_file>\n",
        program_name,
        program_name);
    fprintf(
        stdout,
        "Verify the integrity of enclave remote report or attestation "
        "certificate.\n");
    fprintf(
        stdout,
        "WARNING: %s does not have a stable CLI interface. Use with "
        "caution.\n",
        program_name);
}

int main(int argc, const char* argv[])
{
    const char* report_filename = NULL;
    const char* endorsement_filename = NULL;
    const char* certificate_filename = NULL;
    oe_result_t result = OE_FAILURE;
    int n = 0;

    if (argc <= 2)
    {
        print_syntax(argv[0]);

        if (argc == 2 && memcmp(argv[1], "-h", 2) == 0)
        {
            return 0;
        }

        return 1;
    }

    for (n = 1; n < argc; n++)
    {
        if (memcmp(argv[n], "-r", 2) == 0)
        {
            if (argc > (n - 1))
                report_filename = argv[++n];
        }
        else if (memcmp(argv[n], "-e", 2) == 0)
        {
            if (argc > (n - 1))
                endorsement_filename = argv[++n];
        }
        else if (memcmp(argv[n], "-c", 2) == 0)
        {
            if (argc > (n - 1))
                certificate_filename = argv[++n];
        }
        else
        {
            print_syntax(argv[0]);
            return 1;
        }
    }

    if (report_filename == NULL && certificate_filename == NULL)
    {
        print_syntax(argv[0]);
        return 1;
    }
    else
    {
        if (report_filename != NULL)
        {
            fprintf(stdout, "Verifying report %s...\n", report_filename);
            result = verify_report(report_filename, endorsement_filename);
            fprintf(
                stdout,
                "Report verification %s (%u).\n\n",
                (result == OE_OK) ? "succeeded" : "failed",
                result);
        }

        if (certificate_filename != NULL)
        {
            fprintf(
                stdout, "Verifying certificate %s...\n", certificate_filename);
            result = verify_cert(certificate_filename);
            fprintf(
                stdout,
                "\n\nCertificate verification %s (%u).\n\n",
                (result == OE_OK) ? "succeeded" : "failed",
                result);
        }
    }

    return 0;
}
