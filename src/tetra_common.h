#ifndef TETRA_COMMON_H
#define TETRA_COMMON_H

#include <stdint.h>
#include "tetra_mac_pdu.h"
#include <stdbool.h>
#include <osmocom/core/linuxlist.h>

#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>


#include "tetra_mac_pdu.h"

#ifdef DEBUG
#define DEBUGP(x, args...)	printf(x, ## args)
#else
#define DEBUGP(x, args...)	do { } while (0)
#endif

#define TETRA_SYM_PER_TS	255
#define TETRA_BITS_PER_TS	(TETRA_SYM_PER_TS*2)

/* Chapter 22.2.x */
enum tetra_log_chan {
	TETRA_LC_UNKNOWN,
	/* TMA SAP */
	TETRA_LC_SCH_F,
	TETRA_LC_SCH_HD,
	TETRA_LC_SCH_HU,
	TETRA_LC_STCH,
	TETRA_LC_SCH_P8_F,
	TETRA_LC_SCH_P8_HD,
	TETRA_LC_SCH_P8_HU,

	TETRA_LC_AACH,
	TETRA_LC_TCH,
	TETRA_LC_BSCH,
	TETRA_LC_BNCH,

	/* FIXME: QAM */
};

uint32_t bits_to_uint(const uint8_t *bits, unsigned int len);

/* tetra hack --sq5bpf */
#define HACK_MAX_TIME 5
#define HACK_LIVE_MAX_TIME 1
#define HACK_NUM_STRUCTS 256
struct tetra_hack_struct {
        uint32_t ssi;
	int voice_encr; /* encryption mode for current voice call */
        uint32_t ssi2;
        time_t lastseen;
        int is_encr;
        char curfile[100];
        char comment[100];
        uint16_t callident;
        int seen; /* did we see it before */
};

extern struct  tetra_hack_struct tetra_hack_db[HACK_NUM_STRUCTS];


extern int tetra_hack_live_socket;
extern struct sockaddr_in tetra_hack_live_sockaddr;
extern int tetra_hack_socklen;
extern int tetra_hack_live_socket2;
extern struct sockaddr_in tetra_hack_live_sockaddr2;

extern int tetra_hack_live_idx;
extern int tetra_hack_live_lastseen;
extern int tetra_hack_rxid;

extern int tetra_hack_packet_counter; /* counts packets, wraps around on 65536, can be used for periodic actions */

extern uint32_t tetra_hack_dl_freq, tetra_hack_ul_freq;
extern uint16_t tetra_hack_la;

extern uint8_t  tetra_hack_freq_band;
extern uint8_t  tetra_hack_freq_offset;

#define ENCOPTION_UNKNOWN 0
#define ENCOPTION_DISABLED 1
#define ENCOPTION_ENABLED 2
extern int  tetra_hack_encoption;

extern uint8_t tetra_hack_seen_encryptions;


//int tetra_hack_reassemble_fragments;
extern int tetra_hack_all_sds_as_text;
extern int tetra_hack_allow_encrypted;
void send_encinfo(int send_anyway);

/* end tetra hack --sq5bpf */


#include "tetra_tdma.h"
struct tetra_phy_state {
	struct tetra_tdma_time time;
};
extern struct tetra_phy_state t_phy_state;

struct tetra_mac_state {
	struct llist_head voice_channels;
	struct {
		int is_traffic;
		bool blk1_stolen;
		bool blk2_stolen;
	} cur_burst;
	struct tetra_si_decoded last_sid;

	struct tetra_crypto_state *tcs; /* contains all state relevant to encryption */

	char *dumpdir;	/* Where to save traffic channel dump */
	int ssi;	/* SSI */
	int tsn;	/* Timeslot number */
	int usage_marker; /* Usage marker (if addressed)*/
	int addr_type;
	int voice_encr; /* 0=plain, 2=TEA1 encrypted */
	int voice_encr_idx[64]; /* per-usage-marker encryption state */
};

void tetra_mac_state_init(struct tetra_mac_state *tms);

#define TETRA_CRC_OK	0x1d0f

uint32_t tetra_dl_carrier_hz(uint8_t band, uint16_t carrier, uint8_t offset);
uint32_t tetra_ul_carrier_hz(uint8_t band, uint16_t carrier, uint8_t offset,
			     uint8_t duplex, uint8_t reverse);

const char *tetra_get_lchan_name(enum tetra_log_chan lchan);
const char *tetra_get_sap_name(uint8_t sap);
#endif
