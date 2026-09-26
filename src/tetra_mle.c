#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/bits.h>
#include <osmocom/core/utils.h>

#include "tetra_mle_pdu.h"
#include "tetra_mle.h"
#include "tetra_mm_pdu.h"
#include "tetra_cmce_pdu.h"
#include "tetra_sndcp_pdu.h"
#include "tetra_mle_pdu.h"
#include "tetra_common.h"
#include "tetra_gsmtap.h"

#include "tetra_sds.h"
#include "tetra_mac_pdu.h"
#include "crypto/tetra_crypto.h"
#include "tetra_prim.h"
#include "tetra_upper_mac.h"
#include "tetra_llc_pdu.h"
#include "tetra_llc.h"

/* sq5bpf */
int parse_d_status(struct tetra_mac_state *tms, struct msgb *msg, unsigned int len)
{
	uint8_t *bits = msg->l3h+3;
	int n=0;
	int m=0;
	char tmpstr2[1024];
	char *nis;
	int tmpdu_offset;
	struct tetra_resrc_decoded rsd;

	memset(&rsd, 0, sizeof(rsd));
	tmpdu_offset = macpdu_decode_resource(&rsd, msg->l1h,0); /* FIXME: find out if it's really unencrypted */
	/* strona 269 */
	m=5; uint8_t pdu_type=bits_to_uint(bits+n, m); n=n+m;
	uint8_t cpti;
	uint32_t callingssi;
	uint32_t callingext=0;
	m=2;  cpti=bits_to_uint(bits+n, m); n=n+m;
	switch(cpti)
	{
		case 0: /* SNA */
			m=8; callingssi=bits_to_uint(bits+n, m); n=n+m;
			break;
		case 1: /* SSI */
			m=24; callingssi=bits_to_uint(bits+n, m); n=n+m;
			break;
		case 2: /* TETRA Subscriber Identity (TSI) */
			m=24; callingssi=bits_to_uint(bits+n, m); n=n+m;
			m=24; callingext=bits_to_uint(bits+n, m); n=n+m;
			break;
		case 3: /* reserved ? */
			break;
	}



	m=16; uint16_t precoded_status=bits_to_uint(bits+n, m); n=n+m;

	m=1; uint8_t o_bit=bits_to_uint(bits+n, m); n=n+m;

	if (o_bit) {
		/* TODO: parse optional data */
	}
	printf("\nCPTI:%i CalledSSI:%i CallingSSI:%i CallingEXT:%i Status:%i (0x%4.4x)\n",cpti,rsd.addr.ssi,callingssi,callingext,precoded_status);



	sprintf(tmpstr2,"TETMON_begin FUNC:DSTATUSDEC SSI:%i SSI2:%i STATUS:%i RX:%i TETMON_end",rsd.addr.ssi,callingssi,precoded_status,tetra_hack_rxid);
	sendto(tetra_hack_live_socket, (char *)&tmpstr2, strlen((char *)&tmpstr2)+1, 0, (struct sockaddr *)&tetra_hack_live_sockaddr, tetra_hack_socklen);

}

/* sq5bpf */
int parse_d_release(struct tetra_mac_state *tms, struct msgb *msg, unsigned int len)
{
	uint8_t *bits = msg->l3h+3;
	int n=0;
	int m=0;
	char tmpstr2[1024];
	char *nis;
	int tmpdu_offset;
	struct tetra_resrc_decoded rsd;

	memset(&rsd, 0, sizeof(rsd));
	tmpdu_offset = macpdu_decode_resource(&rsd, msg->l1h,0 ); /* FIXME: find out if it's really unencrypted */
	/* strona 270 */
	m=5; uint8_t pdu_type=bits_to_uint(bits+n, m); n=n+m;
	m=14; uint16_t callident=bits_to_uint(bits+n, m); n=n+m;
	m=5; uint16_t disccause=bits_to_uint(bits+n, m); n=n+m;
	m=6; uint16_t notifindic=bits_to_uint(bits+n, m); n=n+m;
	nis=(notifindic<28)?notification_indicator_strings[notifindic]:"Reserved";
	printf("\nCall identifier:%i Discconnect cause:%i NotificationID:%i (%s)\n",callident,disccause,notifindic,nis);
	sprintf(tmpstr2,"TETMON_begin FUNC:DRELEASEDEC SSI:%i CID:%i NID:%i [%s] RX:%i TETMON_end",rsd.addr.ssi,callident, notifindic,nis,tetra_hack_rxid);
	sendto(tetra_hack_live_socket, (char *)&tmpstr2, strlen((char *)&tmpstr2)+1, 0, (struct sockaddr *)&tetra_hack_live_sockaddr, tetra_hack_socklen);

}

/* sq5bpf */
int parse_d_connect(struct tetra_mac_state *tms, struct msgb *msg, unsigned int len) {
	uint8_t *bits = msg->l3h+3;
	int n=0;
	int m=0;
	char *nis;
	int tmpdu_offset;
	struct tetra_resrc_decoded rsd;
	char buf[1024];
	char buf2[128];

	memset(&rsd, 0, sizeof(rsd));
	tmpdu_offset = macpdu_decode_resource(&rsd, msg->l1h, 0); /* FIXME: find out if it's really unencrypted */
	/* strona 266 */
	m=5; uint8_t pdu_type=bits_to_uint(bits+n, m); n=n+m;
	m=14; uint16_t callident=bits_to_uint(bits+n, m); n=n+m;
	m=4; uint8_t call_timeout=bits_to_uint(bits+n, m); n=n+m;
	m=1; uint8_t hook_method_sel=bits_to_uint(bits+n, m); n=n+m;
	m=1; uint8_t duplex_sel=bits_to_uint(bits+n, m); n=n+m;
	m=2; uint8_t tx_grant=bits_to_uint(bits+n, m); n=n+m;
	m=1; uint8_t tx_req_permission=bits_to_uint(bits+n, m); n=n+m;
	m=1; uint8_t call_ownership=bits_to_uint(bits+n, m); n=n+m;
	m=1; uint8_t o_bit=bits_to_uint(bits+n, m); n=n+m;
	printf("\nCall Identifier:%i Call timeout:%i hook_method:%i Duplex:%i TX_Grant:%i TX_Request_permission:%i Call ownership:%i\n",callident,call_timeout,hook_method_sel,duplex_sel,tx_grant,tx_req_permission,call_ownership);
	sprintf(buf,"TETMON_begin FUNC:DCONNECTDEC SSI:%i IDX:%i CID:%i CALLOWN:%i",rsd.addr.ssi,rsd.addr.usage_marker,callident,call_ownership);
	if (o_bit) {

		m=1; uint8_t pbit_callpri=bits_to_uint(bits+n, m); n=n+m;
		if (pbit_callpri) {
			m=4; uint8_t callpri=bits_to_uint(bits+n, m); n=n+m;
			printf("Call priority:%i ",callpri);
		}

		m=1; uint8_t pbit_bsi=bits_to_uint(bits+n, m); n=n+m;
		if (pbit_bsi) {
			m=8; uint8_t basic_service_information=bits_to_uint(bits+n, m); n=n+m;
			printf("Basic service information:%i ", basic_service_information);
		}

		m=1; uint8_t pbit_tmpaddr=bits_to_uint(bits+n, m); n=n+m;
		if (pbit_tmpaddr) {
			m=24; uint32_t temp_addr=bits_to_uint(bits+n, m); n=n+m;
			printf("Temp address:%i ",temp_addr);
			sprintf(buf2," SSI2:%i",temp_addr);
			strcat(buf,buf2);
		}
		m=1; uint8_t pbit_nid=bits_to_uint(bits+n, m); n=n+m;
		if (pbit_nid) {
			m=6; uint8_t notifindic=bits_to_uint(bits+n, m); n=n+m;
			nis=(notifindic<28)?notification_indicator_strings[notifindic]:"Reserved";
			printf("Notification indicator:%i [%s] ",notifindic,nis);
			sprintf(buf2," NID:%i [%s]",notifindic,nis);
			strcat(buf,buf2);

		}
		printf("\n");
	}
	sprintf(buf2," RX:%i TETMON_end",tetra_hack_rxid);
	strcat(buf,buf2);
	sendto(tetra_hack_live_socket, (char *)&buf, strlen((char *)&buf)+1, 0, (struct sockaddr *)&tetra_hack_live_sockaddr, tetra_hack_socklen);

}

int parse_d_txgranted(struct tetra_mac_state *tms, struct msgb *msg, unsigned int len) {
	uint8_t *bits = msg->l3h+3;
	int n=0;
	int m=0;
	char *nis;
	int tmpdu_offset;
	struct tetra_resrc_decoded rsd;
	char buf[1024];
	char buf2[128];

	memset((struct tetra_resrc_decoded *)&rsd, 0, sizeof(rsd));
	tmpdu_offset = macpdu_decode_resource((struct tetra_resrc_decoded *)&rsd, msg->l1h,0 ); /* FIXME: find out if it's really unencrypted */
	/* strona 271 */
	m=5; uint8_t pdu_type=bits_to_uint(bits+n, m); n=n+m;
	m=14; uint16_t callident=bits_to_uint(bits+n, m); n=n+m;
	m=2; uint8_t tx_grant=bits_to_uint(bits+n, m); n=n+m;
	m=1; uint8_t tx_req_permission=bits_to_uint(bits+n, m); n=n+m;
	m=1; uint8_t enc_control=bits_to_uint(bits+n, m); n=n+m;
	m=1; uint8_t reserved=bits_to_uint(bits+n, m); n=n+m;
	m=1; uint8_t o_bit=bits_to_uint(bits+n, m); n=n+m;
	printf("\nCall Identifier:%i TX_Grant:%i TX_Request_permission:%i Encryption control:%i\n",callident,tx_grant,tx_req_permission,enc_control);
	sprintf(buf,"TETMON_begin FUNC:DTXGRANTDEC SSI:%i IDX:%i CID:%i TXGRANT:%i TXPERM:%i ENCC:%i",rsd.addr.ssi,rsd.addr.usage_marker,callident,tx_grant,tx_req_permission,enc_control);
	if (o_bit) {
		m=1; uint8_t pbit_nid=bits_to_uint(bits+n, m); n=n+m;
		if (pbit_nid) {
			m=6; uint8_t notifindic=bits_to_uint(bits+n, m); n=n+m;
			nis=(notifindic<28)?notification_indicator_strings[notifindic]:"Reserved";
			printf("Notification indicator:%i [%s] ",notifindic,nis);
			sprintf(buf2," NID:%i [%s]",notifindic,nis);
			strcat(buf,buf2);

		}
		m=1; uint8_t pbit_tpti=bits_to_uint(bits+n, m); n=n+m;
		if (pbit_tpti) {
			m=2; uint8_t tpti=bits_to_uint(bits+n, m); n=n+m;
			uint32_t txssi;
			uint32_t txssiext;

			sprintf(buf2," TPTI:%i",tpti);
			strcat(buf,buf2);

			switch(tpti)
			{
				case 0: /* SNA , this isn't defined for D-TX GRANTED */
					m=8; txssi=bits_to_uint(bits+n, m); n=n+m;
					sprintf(buf2," SSI2:%i",txssi);
					strcat(buf,buf2);

					break;
				case 1: /* SSI */
					m=24; txssi=bits_to_uint(bits+n, m); n=n+m;
					sprintf(buf2," SSI2:%i",txssi);
					strcat(buf,buf2);
					break;
				case 2: /* TETRA Subscriber Identity (TSI) */
					m=24; txssi=bits_to_uint(bits+n, m); n=n+m;
					m=24; txssiext=bits_to_uint(bits+n, m); n=n+m;
					sprintf(buf2," SSI2:%i SSIEXT:%i",txssi,txssiext);
					strcat(buf,buf2);
					break;
				case 3: /* reserved ? */
					break;
			}


		}
		/* TODO: type 3/4 elements */
		printf("\n");
	}
	sprintf(buf2," RX:%i TETMON_end",tetra_hack_rxid);
	strcat(buf,buf2);
	sendto(tetra_hack_live_socket, (char *)&buf, strlen((char *)&buf)+1, 0, (struct sockaddr *)&tetra_hack_live_sockaddr, tetra_hack_socklen);
}


uint parse_d_setup(struct tetra_mac_state *tms, struct msgb *msg, unsigned int len)
{
	uint8_t *bits = msg->l3h+3;
	int n=0;
	int m=0;
	uint32_t callingssi=0;
	uint32_t callingext=0;
	char tmpstr2[1024];
	struct tetra_resrc_decoded rsd;
	int tmpdu_offset;
	uint16_t notifindic=0;
	uint32_t tempaddr=0;
	uint16_t cpti=0;

	memset(&rsd, 0, sizeof(rsd));
	tmpdu_offset = macpdu_decode_resource(&rsd, msg->l1h, 0); /* FIXME: find out if it's really unencrypted */



	/* strona 270, opisy strona 280 */
	m=5; uint8_t pdu_type=bits_to_uint(bits+n, m); n=n+m;

	m=14; uint16_t callident=bits_to_uint(bits+n, m); n=n+m;
	m=4; uint16_t calltimeout=bits_to_uint(bits+n, m);  n=n+m;
	m=1; uint16_t hookmethod=bits_to_uint(bits+n, m); n=n+m;
	m=1; uint16_t duplex=bits_to_uint(bits+n, m); n=n+m;
	m=8; uint8_t basicinfo=bits_to_uint(bits+n, m); n=n+m;
	m=2; uint16_t txgrant=bits_to_uint(bits+n, m); n=n+m;
	m=1; uint16_t txperm=bits_to_uint(bits+n, m); n=n+m;
	m=4; uint16_t callprio=bits_to_uint(bits+n, m); n=n+m;
	m=1; uint8_t obit=bits_to_uint(bits+n, m); n=n+m;
	if (obit)
	{
		m=1; uint8_t pbit_notifindic=bits_to_uint(bits+n, m); n=n+m;
		if (pbit_notifindic) {
			m=6;  notifindic=bits_to_uint(bits+n, m); n=n+m;
		}
		m=1; uint8_t pbit_tempaddr=bits_to_uint(bits+n, m); n=n+m;
		if (pbit_tempaddr) {
			m=24;  tempaddr=bits_to_uint(bits+n, m); n=n+m;
		}
		m=1; uint8_t pbit_cpti=bits_to_uint(bits+n, m); n=n+m;
		if (pbit_cpti) {
			m=2;  cpti=bits_to_uint(bits+n, m); n=n+m;
			switch(cpti)
			{
				case 0: /* SNA */
					m=8; callingssi=bits_to_uint(bits+n, m); n=n+m;
					break;
				case 1: /* SSI */
					m=24; callingssi=bits_to_uint(bits+n, m); n=n+m;
					break;
				case 2: /* TETRA Subscriber Identity (TSI) */
					m=24; callingssi=bits_to_uint(bits+n, m); n=n+m;
					m=24; callingext=bits_to_uint(bits+n, m); n=n+m;
					break;
				case 3: /* reserved ? */
					break;
			}
		}

	}
	printf ("\nCall identifier:%i  Call timeout:%i  Hookmethod:%i  Duplex:%i\n",callident,calltimeout,hookmethod,duplex);
	printf("Basicinfo:0x%2.2X  Txgrant:%i  TXperm:%i  Callprio:%i\n",basicinfo,txgrant,txperm,callprio);
	printf("NotificationID:%i  Tempaddr:%i CPTI:%i  CallingSSI:%i  CallingExt:%i\n",notifindic,tempaddr,cpti,callingssi,callingext);

	sprintf(tmpstr2,"TETMON_begin FUNC:DSETUPDEC IDX:%i SSI:%i SSI2:%i CID:%i NID:%i RX:%i TETMON_end",rsd.addr.usage_marker,rsd.addr.ssi,callingssi,callident,notifindic,tetra_hack_rxid);
	sendto(tetra_hack_live_socket, (char *)&tmpstr2, strlen((char *)&tmpstr2)+1, 0, (struct sockaddr *)&tetra_hack_live_sockaddr, tetra_hack_socklen);
}

/* decode 18.5.17 Neighbour cell information for CA */
/* str 535, przyklad str 1294 */
int parse_nci_ca( uint8_t *bits)
{
	int n,m;
	char buf[1024];
	char buf2[128];
	char freqinfo[128];
	n=0;
	m=5; uint8_t cell_id=bits_to_uint(bits+n, m); n=n+m;
	m=2; uint8_t cell_reselection=bits_to_uint(bits+n, m); n=n+m;
	m=1; uint8_t neig_cell_synced=bits_to_uint(bits+n, m); n=n+m;
	m=2; uint8_t cell_load=bits_to_uint(bits+n, m); n=n+m;
	m=12; uint16_t main_carrier_num=bits_to_uint(bits+n, m); n=n+m;
	/* the band and offset info is from the sysinfo message, not sure if this is correct */
	sprintf(buf," NCI:[cell_id:%i cell_resel:%i neigh_synced:%i cell_load:%i carrier:%i %iHz",cell_id,cell_reselection,neig_cell_synced,cell_load,main_carrier_num,tetra_dl_carrier_hz(tetra_hack_freq_band, main_carrier_num, tetra_hack_freq_offset));

	sprintf(freqinfo,"TETMON_begin FUNC:FREQINFO1 DLF:%i",tetra_dl_carrier_hz(tetra_hack_freq_band, main_carrier_num, tetra_hack_freq_offset));

	m=1; uint8_t obit=bits_to_uint(bits+n, m); n=n+m;
	if (obit) {
		m=1; uint8_t pbit_main_carrier_num_ext=bits_to_uint(bits+n, m); n=n+m;
		if (pbit_main_carrier_num_ext) {
			m=4; uint8_t freq_band=bits_to_uint(bits+n, m); n=n+m;
			m=2; uint8_t freq_offset=bits_to_uint(bits+n, m); n=n+m;
			m=3; uint8_t duplex_spacing=bits_to_uint(bits+n, m); n=n+m;
			m=1; uint8_t reverse=bits_to_uint(bits+n, m); n=n+m;
			uint32_t dlfext=tetra_dl_carrier_hz(freq_band, main_carrier_num, freq_offset);
			uint32_t ulfext=tetra_ul_carrier_hz(freq_band, main_carrier_num, freq_offset,duplex_spacing,reverse);

			sprintf(buf2," band:%i offset:%i freq:%iHz uplink:%iHz (duplex:%i rev:%i)",freq_band,freq_offset,dlfext,ulfext,duplex_spacing,reverse);
			strcat(buf,buf2);
			sprintf(buf2,"TETMON_begin FUNC:FREQINFO1 DLF:%i ULF:%i",dlfext, ulfext);
			strcat(freqinfo,buf2);
		}
		m=1; uint8_t pbit_mcc=bits_to_uint(bits+n, m); n=n+m;
		if (pbit_mcc) {
			m=10; uint16_t mcc=bits_to_uint(bits+n, m); n=n+m;
			sprintf(buf2," MCC:%i",mcc);
			strcat(buf,buf2);
			sprintf(buf2," MCC:%4.4x",mcc);
			strcat(freqinfo,buf2);
		}

		m=1; uint8_t pbit_mnc=bits_to_uint(bits+n, m); n=n+m;
		if (pbit_mnc) {
			m=14; uint16_t mnc=bits_to_uint(bits+n, m); n=n+m;
			sprintf(buf2," MNC:%i",mnc);
			strcat(buf,buf2);
			sprintf(buf2," MNC:%4.4x",mnc);
			strcat(freqinfo,buf2);
		}
		m=1; uint8_t pbit_la=bits_to_uint(bits+n, m); n=n+m;
		if (pbit_la) {
			m=14; uint16_t la=bits_to_uint(bits+n, m); n=n+m;
			sprintf(buf2," LA:%i",la);
			strcat(buf,buf2);
			strcat(freqinfo,buf2);
		}

		m=1; uint8_t pbit_max_ms_txpower=bits_to_uint(bits+n, m); n=n+m;
		if (pbit_max_ms_txpower) {
			m=3; uint8_t max_ms_txpower=bits_to_uint(bits+n, m); n=n+m;
		}

		m=1; uint8_t pbit_min_rx_level=bits_to_uint(bits+n, m); n=n+m;
		if (pbit_min_rx_level) {
			m=4; uint8_t min_rx_level=bits_to_uint(bits+n, m); n=n+m;
		}

		m=1; uint8_t pbit_subscr_class=bits_to_uint(bits+n, m); n=n+m;
		if (pbit_subscr_class) {
			m=16; uint16_t subscr_class=bits_to_uint(bits+n, m); n=n+m;
		}

		m=1; uint8_t pbit_bs_srv_details=bits_to_uint(bits+n, m); n=n+m;
		if (pbit_bs_srv_details) {
			m=12; uint16_t bs_srv_details=bits_to_uint(bits+n, m); n=n+m;
		}

		m=1; uint8_t pbit_timeshare_info=bits_to_uint(bits+n, m); n=n+m;
		if (pbit_timeshare_info) {
			m=5; uint8_t timeshare_info=bits_to_uint(bits+n, m); n=n+m;
		}

		m=1; uint8_t pbit_tdma_frame_offset=bits_to_uint(bits+n, m); n=n+m;
		if (pbit_tdma_frame_offset) {
			m=6; uint8_t tdma_frame_offset=bits_to_uint(bits+n, m); n=n+m;
		}
	}
	sprintf(buf2,"] ");
	strcat(buf,buf2);
	printf("%s",buf);

	sprintf(buf2," RX:%i TETMON_end",tetra_hack_rxid);
	strcat(freqinfo,buf2);
	sendto(tetra_hack_live_socket, (char *)&freqinfo, 128, 0, (struct sockaddr *)&tetra_hack_live_sockaddr, tetra_hack_socklen);

	return(n);
}

uint parse_d_nwrk_broadcast(struct tetra_mac_state *tms, struct msgb *msg, unsigned int len)
{
	uint8_t *bits = msg->l3h;
	int n,m,i;

	/* TMLE_PDISC_MLE 3 bits
	 * TMLE_PDUT_D_NWRK_BROADCAST 3 bits */
	n=3+3;

	m=16; uint16_t cell_reselect_parms=bits_to_uint(bits+n, m); n=n+m;
	m=2; uint16_t cell_load=bits_to_uint(bits+n, m); n=n+m;
	m=1; uint16_t optional_elements=bits_to_uint(bits+n, m); n=n+m;
	printf("\nD_NWRK_BROADCAST:[ cell_reselect:0x%4.4x cell_load:%i", cell_reselect_parms,cell_load);
	if (optional_elements) {
		m=1; uint16_t pbit_tetra_time=bits_to_uint(bits+n, m); n=n+m;
		if (pbit_tetra_time)
		{
			m=24; uint32_t tetra_time_utc=bits_to_uint(bits+n, m); n=n+m;
			m=1; uint8_t tetra_time_offset_sign=bits_to_uint(bits+n, m); n=n+m;
			m=6; uint8_t tetra_time_offset=bits_to_uint(bits+n, m); n=n+m;
			m=6; uint8_t tetra_time_year=bits_to_uint(bits+n, m); n=n+m;
			m=11; uint16_t tetra_time_reserved=bits_to_uint(bits+n, m); n=n+m; /* must be 0x7ff */
			printf(" time[secs:%i offset:%c%imin year:%i reserved:0x%4.4x]",tetra_time_utc,tetra_time_offset_sign?'-':'+',tetra_time_offset*15,2000+tetra_time_year,tetra_time_reserved);
			/* we could decode the time here, but it is not accurate on the networks that i see anyway */
		}

		m=1; uint16_t pbit_neigh_cells=bits_to_uint(bits+n, m); n=n+m;

		//      printf(" pbit_tetra_time:%i pbit_neigh_cells:%i",pbit_tetra_time,pbit_neigh_cells);
		if (pbit_neigh_cells)
		{
			m=3; uint16_t num_neigh_cells=bits_to_uint(bits+n, m); n=n+m;
			printf(" num_cells:%i",num_neigh_cells);
			for (i=0;i<num_neigh_cells;i++) {
				m=parse_nci_ca(bits+n); n=n+m;
			}

		}


	}
	printf("] RX:%i\n",tetra_hack_rxid);

}





/* Receive TL-SDU (LLC SDU == MLE PDU) */
int rx_tl_sdu(struct tetra_mac_state *tms, struct msgb *msg, unsigned int len)
{
	uint8_t *bits = msg->l3h;
	uint8_t mle_pdisc = bits_to_uint(bits, 3);
	char tmpstr[1024];
	int ok=1;

	printf("TL-SDU(%s): %s ", tetra_get_mle_pdisc_name(mle_pdisc),
			osmo_ubit_dump(bits, len));
	printf("\nSQ5BPF 1: msglen=%i len=%i l1len=%i l2len=%i l3len=%i diff1=%i\n",
			msg->len, len, msgb_l1len(msg), msgb_l2len(msg), msgb_l3len(msg),msg->len - len);
	fflush(stdout);
	if (msg->len = len) ok=0;

	switch (mle_pdisc) {
		case TMLE_PDISC_MM: {
					    uint8_t pdut = bits_to_uint(bits+3, 4);
					    printf("%s ", tetra_get_mm_pdut_name(pdut, 0));
					    switch (pdut) {
						    case TMM_PDU_T_D_AUTH: {
										   struct msgb *gsmtap_msg;
										   struct tetra_tdma_time tm = t_phy_state.time;
										   uint8_t auth_sub_type;
										   const uint8_t *cur = bits + 3 + 4;

										   auth_sub_type = bits_to_uint(cur, 2);
										   cur += 2;

										   printf("%s", tetra_get_auth_sub_type_name(auth_sub_type));

										   if (auth_sub_type == TMM_AUTH_ST_DEMAND) {
											   uint8_t rand1[10];
											   uint8_t ra[10];
											   for (int i = 0; i < 10; i++) {
												   rand1[i] = bits_to_uint(cur, 8);
												   cur += 8;
											   }
											   for (int i = 0; i < 10; i++) {
												   ra[i] = bits_to_uint(cur, 8);
												   cur += 8;
											   }
											   printf(" RAND1=%s RA=%s", osmo_hexdump(rand1, sizeof(rand1)),
													   osmo_hexdump(ra, sizeof(ra)));
										   } else {
											   int payload_bits = len - (3 + 4 + 2);
											   int payload_bytes = (payload_bits + 7) / 8;
											   uint8_t payload[256];
											   for (int i = 0; i < payload_bytes; i++) {
												   payload[i] = bits_to_uint(cur, 8);
												   cur += 8;
											   }
											   printf(" DATA=%s", osmo_hexdump(payload, payload_bytes));
										   }
										   printf("\n");

										   /* Provide a timestamp close to the burst that carried
										    * the last fragment and ensure the timeslot is in the
										    * expected 0..3 range for GSMTAP. */
										   gsmtap_msg = tetra_gsmtap_makemsg(&tm, TETRA_LC_STCH,
												   tms->tsn - 1, 0,
												   0, 0, bits, len, tms);
										   if (gsmtap_msg)
											   tetra_gsmtap_sendmsg(gsmtap_msg);
										   break;
									   }
						    case TMM_PDU_T_D_OTAR: {
										   struct msgb *gsmtap_msg;
										   struct tetra_tdma_time tm = t_phy_state.time;
										   const uint8_t *cur = bits + 3 + 4;
										   uint8_t otar_sub_type = bits_to_uint(cur, 4);
										   cur += 4;
										   int payload_bits = len - (3 + 4 + 4);
										   int payload_bytes = (payload_bits + 7) / 8;
										   uint8_t payload[256];
										   for (int i = 0; i < payload_bytes; i++) {
											   payload[i] = bits_to_uint(cur, 8);
											   cur += 8;
										   }
										   printf("%s DATA=%s\n", tetra_get_otar_sub_type_name(otar_sub_type),
												   osmo_hexdump(payload, payload_bytes));

										   gsmtap_msg = tetra_gsmtap_makemsg(&tm, TETRA_LC_STCH,
												   tms->tsn - 1, 0,
												   0, 0, bits, len, tms);
										   if (gsmtap_msg)
											   tetra_gsmtap_sendmsg(gsmtap_msg);
										   break;
									   }
						    default:
									   printf("\n");
									   break;
					    }
					    break;
				    }
		case TMLE_PDISC_CMCE:
				    printf("%s\n", tetra_get_cmce_pdut_name(bits_to_uint(bits+3, 5), 0));
				    if (ok) {
					    switch(bits_to_uint(bits+3, 5)) {
						    case TCMCE_PDU_T_D_SETUP:
							    parse_d_setup(tms,msg,len);
							    break;

						    case TCMCE_PDU_T_D_CONNECT:
							    parse_d_connect(tms,msg,len);
							    break;

						    case TCMCE_PDU_T_D_RELEASE:
							    parse_d_release(tms,msg,len);
							    break;

						    case TCMCE_PDU_T_D_TX_GRANTED:
							    parse_d_txgranted(tms,msg,len);
							    break;

						    case TCMCE_PDU_T_D_STATUS:
							    parse_d_status(tms,msg,len);
							    break;

						    case TCMCE_PDU_T_D_SDS_DATA:
							    sprintf(tmpstr,"TETMON_begin FUNC:SDS [%s] TETMON_end",osmo_ubit_dump(bits, len));
							    sendto(tetra_hack_live_socket, (char *)&tmpstr, strlen((char *)&tmpstr)+1, 0, (struct sockaddr *)&tetra_hack_live_sockaddr, tetra_hack_socklen);
							    parse_d_sds_data(tms,msg,len);
							    break;

					    }
				    }



				    break;
		case TMLE_PDISC_SNDCP:
				    printf("%s ", tetra_get_sndcp_pdut_name(bits_to_uint(bits+3, 4), 0));
				    printf(" NSAPI=%u PCOMP=%u, DCOMP=%u",
						    bits_to_uint(bits+3+4, 4),
						    bits_to_uint(bits+3+4+4, 4),
						    bits_to_uint(bits+3+4+4+4, 4));
				    printf(" V%u, IHL=%u",
						    bits_to_uint(bits+3+4+4+4+4, 4),
						    4*bits_to_uint(bits+3+4+4+4+4+4, 4));
				    printf(" Proto=%u\n",
						    bits_to_uint(bits+3+4+4+4+4+4+4+64, 8));
				    break;
		case TMLE_PDISC_MLE:
				    printf("%s\n", tetra_get_mle_pdut_name(bits_to_uint(bits+3, 3), 0));
				    parse_d_nwrk_broadcast(tms,msg,len);

				    break;
		default:
				    break;
	}
	return len;
}
