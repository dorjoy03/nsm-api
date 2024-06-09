#include <stdio.h>
#include <nsm.h>

const char *error_code_to_string(int err)
{
    const char *resp;
    switch (err) {
    case 0:
        resp = "success";
        break;
    case 1:
        resp = "invalid argument";
        break;
    case 2:
        resp = "invalid index";
        break;
    case 3:
        resp = "invalid response";
        break;
    case 4:
        resp = "readonly index";
        break;
    case 5:
        resp = "invalid operation";
        break;
    case 6:
        resp = "buffer too small";
        break;
    case 7:
        resp = "input too large";
        break;
    case 8:
        resp = "internal error";
        break;
    default:
        resp = "uknown error number";
        break;
    }

    return resp;
}

int main()
{
    int fd, ret;
    struct NsmDescription desc;
    long unsigned int rnd_size = 64;
    uint8_t rnd[64];
    uint8_t data[100];
    uint32_t data_len = 100;

    fd = nsm_lib_init();
    if (fd < 0) {
        fprintf(stderr, "Failed to init nsm lib\n");
        exit(1);
    }

    // GetRandom
    ret = nsm_get_random(fd, rnd, &rnd_size);
    if (ret != ERROR_CODE_SUCCESS) {
        fprintf(stderr, "Failed GetRandom, error: %s\n\n", error_code_to_string(ret));
        exit(1);
    }

    printf("GetRandom response: ");
    for (int i = 0; i < rnd_size; ++i) {
        printf("%d ", rnd[i]);
    }
    printf("\n\n");

    // DescribeNSM
    ret = nsm_get_description(fd, &desc);
    if (ret != ERROR_CODE_SUCCESS) {
        fprintf(stderr, "Failed DescribeNSM, error: %s\n\n", error_code_to_string(ret));
        exit(1);
    }
    printf("DescribeNSM reponse:\n");
    printf("version_major %d\n", desc.version_major);
    printf("version_minor %d\n", desc.version_minor);
    printf("version_patch %d\n", desc.version_patch);
    printf("module_id     %.*s\n", desc.module_id_len, desc.module_id);
    printf("max_pcrs      %d\n", desc.max_pcrs);
    printf("locked_pcrs: ");
    for (int i = 0; i < desc.locked_pcrs_len; ++i) {
        printf("%d ", desc.locked_pcrs[i]);
    }
    printf("\n\n");

    // ExtendPCR
    ret = nsm_extend_pcr(fd, 0, "hello", 5, data, &data_len);
    if (ret != ERROR_CODE_SUCCESS) {
        fprintf(stderr, "Failed ExtendPCR, error: %s\n\n", error_code_to_string(ret));
    } else {
        printf("ExtendPCR response: %.*s\n\n", data_len, data);
    }

    // DescribePCR
    bool locked = true;
    data_len = 100;
    ret = nsm_describe_pcr(fd, 0, &locked, data, &data_len);
    if (ret != ERROR_CODE_SUCCESS) {
        fprintf(stderr, "Failed DescribePCR, error: %s\n\n", error_code_to_string(ret));
    } else {
        printf("DescribePCR response: locked %d, data %.*s\n\n", locked, data_len, data);
    }

    // Attestation
    data_len = 100;
    ret = nsm_get_attestation_doc(fd, "hello", 5, "hello", 5, "hello", 5, data, &data_len);
    if (ret != ERROR_CODE_SUCCESS) {
        fprintf(stderr, "Failed Attestation, error: %s\n\n", error_code_to_string(ret));
    } else {
        printf("Attestation response: %.*s\n\n", data_len, data);
    }

    // LockPCR
    ret = nsm_lock_pcr(fd, 0);
    if (ret != ERROR_CODE_SUCCESS) {
        fprintf(stderr, "Failed LockPCR, error: %s\n\n", error_code_to_string(ret));
    } else {
        printf("LockPCR succeeded\n\n");
    }

    // LockPCRs
    ret = nsm_lock_pcrs(fd, 0);
    if (ret != ERROR_CODE_SUCCESS) {
        fprintf(stderr, "Failed LockPCRs, error: %s\n\n", error_code_to_string(ret));
    } else {
        printf("LockPCRs succeeded\n\n");
    }
    return 0;
}
