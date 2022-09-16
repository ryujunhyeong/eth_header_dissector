#define _CRT_SECURE_NO_WARNINGS
#include <openssl/aes.h>
#include <openssl/modes.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>
using namespace std;
#define BYTES_SIZE 4096
#define KEY_SIZE 4096
unsigned char header[KEY_SIZE] = { 0, }, ckey[KEY_SIZE] = { 0, }, iv[KEY_SIZE] = { 0, }, header2[KEY_SIZE] = { 0, };
int length;
struct ctr_state {
    unsigned char ivec[AES_BLOCK_SIZE], ecount[AES_BLOCK_SIZE];
    unsigned int num;
};
AES_KEY key;
void init_ctr(struct ctr_state* state, const unsigned char iv[16]) {
    state->num = 0;
    memset(state->ecount, 0, AES_BLOCK_SIZE);
    memset(state->ivec + 16, 0, 16);
    memcpy(state->ivec, iv, 16);
}
void epoch(time_t rawtime, FILE* fp)
{
    struct tm  ts;
    char buf[80];
    ts = *localtime(&rawtime);
    strftime(buf, sizeof(buf), "%a %Y-%m-%d %H:%M:%S %Z", &ts);
    for (int i = 15; i < 23;i++)
        fprintf(fp, "%c",buf[i]);
    printf("%s\n", buf);
}

void encrypt(unsigned char* indata, unsigned char* outdata, int bytes_read) {
    int i = 0;
    int mod_len = 0;
    AES_set_encrypt_key(ckey, 128, &key);
    if (bytes_read < BYTES_SIZE) {
        struct ctr_state state;
        init_ctr(&state, iv);
        CRYPTO_ctr128_encrypt(indata, outdata, bytes_read, &key, state.ivec, state.ecount, &state.num, (block128_f)AES_encrypt);
        return;
    }
    for (i = BYTES_SIZE; i <= bytes_read; i += BYTES_SIZE) {
        struct ctr_state state;
        init_ctr(&state, iv);
        CRYPTO_ctr128_encrypt(indata, outdata, BYTES_SIZE, &key, state.ivec, state.ecount, &state.num, (block128_f)AES_encrypt);
        indata += BYTES_SIZE;
        outdata += BYTES_SIZE;
    }
    mod_len = bytes_read % BYTES_SIZE;
    if (mod_len != 0) {
        struct ctr_state state;
        init_ctr(&state, iv);
        CRYPTO_ctr128_encrypt(indata, outdata, mod_len, &key, state.ivec, state.ecount, &state.num, (block128_f)AES_encrypt);
    }
}
void Hex_Changer(char* arr, int length, unsigned char* temporary) {
    int i, f1, f2;
    for (i = 1; i < length; i += 2) {
        if ((int)arr[i - 1] >= 'a' && (int)arr[i - 1] <= 'z')
            f1 = (int)arr[i - 1] - 'a' + 10;
        else
            f1 = (int)arr[i - 1] - '0';
        if ((int)arr[i] >= 'a' && (int)arr[i] <= 'z')
            f2 = (int)arr[i] - 'a' + 10;
        else
            f2 = (int)arr[i] - '0';
        temporary[i / 2] = f1 * 16 + f2;
    }
}
void Packet_Print(unsigned char* header, int start, int end) {
    for (int i = start; i < end; i++)
        if ((int)header[i] < 16)
            printf("0%x", (int)header[i]);
        else
            printf("%x", header[i]);
}
int main(int argc, char *argv[])
{
    int i = 0, j = 0, qqqq=0;
    FILE* fp;
    FILE* fp2;
    FILE* fp3;
    FILE* fp4;
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t * pcap = pcap_open_offline("capture.pcap", errbuff);
    struct pcap_pkthdr *header_pcap;
    const u_char *data_pcap;
    u_int packetCount = 0; 
    FILE* fp5;
    fp5 = fopen("change_packet.pcap", "w");

    while (int returnValue = pcap_next_ex(pcap, &header_pcap, &data_pcap) >= 0)
    {
        fprintf(fp5, "+---------+---------------+----------+\n");
        epoch(header_pcap->ts.tv_sec, fp5);
        fprintf(fp5, ",%.3d,%.3d   ETHER\n", header_pcap->ts.tv_usec / 1000, header_pcap->ts.tv_usec % 1000);
        for (u_int i = 0; (i <= header_pcap->caplen); i++) {
            fprintf(fp5, "%.2x", data_pcap[i]);
        }
        fprintf(fp5,"\n");
    }
    fclose(fp5);

    for(int q=0;q<2;q++){
        fp = fopen("change_packet.pcap", "r");
        fp2 = fopen("decode.pcap", "w");
        fclose(fp2);
        while (NULL != fp) {
            printf("%d\n", qqqq++);
            fp2 = fopen("decode.pcap", "a");
            i++;
            char temporary[BYTES_SIZE] = { 0, };
            char temp[BYTES_SIZE] = { 0, };
            char iv_key[BYTES_SIZE] = { 0, };
            fgets(temporary, sizeof(temporary), fp);
            if (i % 3 == 1) {
                fprintf(fp2, "+---------+---------------+----------+\n");
            }
            else if (i % 3 == 2) {
                fprintf(fp2, "%s", temporary);
            }
            else {
                fprintf(fp2, "|0   ");
                for (j = 0; j < 84; j++) {
                    if (j % 2 == 0) fprintf(fp2, "|");
                    fprintf(fp2, "%c", temporary[j]);
                }
                for (j = 84; j < 116; j++) {
                    iv_key[j - 84] = temporary[j];
                    if (j % 2 == 0) fprintf(fp2, "|");
                    fprintf(fp2, "%c", temporary[j]);
                }
                for (j = 116; j < strlen(temporary); j++) {
                    temp[j - 116] = temporary[j];
                }
                length = strlen(temp);
                if (length == 0) break;
                Hex_Changer(temp, length, header);
                Hex_Changer(iv_key, 32, iv);
                fp3 = fopen("key.txt", "r");
                while (NULL != fp3) {
                    for (int k = 0; k <length/2; k++)
                        header2[k] = header[k];
                    fgets(temporary, sizeof(temporary), fp3);
                    if (strlen(temporary) == 0) break;
                    Hex_Changer(temporary, 32, ckey);
                    encrypt(header2, header2, length / 2);
                    if (header2[0] == 100 && header2[1] == 105 && header2[2]==115 &&header2[3]==99&&header2[4]==118)
                        break;
                    for (int qq = 0; qq < 50; qq++)
                        temporary[qq] = '\0';
                }
                fclose(fp3);
                for (j = 0; j < length / 2; j++)
                    fprintf(fp2, "|%.2x", header2[j]);
                fprintf(fp2, "\n\n");
                if (header2[8] == 0) {
                    fp4 = fopen("key.txt", "a");
                    fprintf(fp4, "\n");
                    for (j = 23; j < 39; j++)
                        fprintf(fp4,"%.2x", header2[j]);
                    fclose(fp4);
                }
            }
            fclose(fp2);
        }
        fclose(fp);
        fclose(fp2);
    }
    
}
