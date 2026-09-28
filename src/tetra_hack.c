#include "tetra_common.h"

struct  tetra_hack_struct tetra_hack_db[HACK_NUM_STRUCTS];


int tetra_hack_live_socket;
struct sockaddr_in tetra_hack_live_sockaddr;
int tetra_hack_socklen;

/* Second telive instance (unencrypted monitor) */
int tetra_hack_live_socket2;
struct sockaddr_in tetra_hack_live_sockaddr2;

int tetra_hack_live_idx;
int tetra_hack_live_lastseen;
int tetra_hack_rxid;

int tetra_hack_packet_counter; /* counts packets, wraps around on 65536, can be used for periodic actions */

uint32_t tetra_hack_dl_freq, tetra_hack_ul_freq;
uint16_t tetra_hack_la;

uint8_t  tetra_hack_freq_band;
uint8_t  tetra_hack_freq_offset;

#define ENCOPTION_UNKNOWN 0
#define ENCOPTION_DISABLED 1
#define ENCOPTION_ENABLED 2
int  tetra_hack_encoption;

uint8_t tetra_hack_seen_encryptions;


//int tetra_hack_reassemble_fragments;
int tetra_hack_all_sds_as_text;
int tetra_hack_allow_encrypted;
void send_encinfo(int send_anyway);

