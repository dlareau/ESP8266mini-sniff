// This-->tab == "structures.h"

#define ETH_MAC_LEN 6

#define PROBE_REQUEST 4
#define PROBE_RESPONSE 5
#define BEACON 8
#define CLIENT 15

uint8_t broadcast1[3] = { 0x01, 0x00, 0x5e };
uint8_t broadcast2[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
uint8_t broadcast3[3] = { 0x33, 0x33, 0x00 };

// 6 + 33 + 1 + 1 + 1 + 1 = 43
struct managementInfo {
  uint8_t   mac_addr[ETH_MAC_LEN];
  char      ssid[33];
  uint8_t   ssid_len;
  uint8_t   channel;
  uint8_t   err;
  signed    rssi;
};

// 6 + 6 + 6 + 1 + 1 + 1 = 21
struct dataInfo {
  uint8_t   bssid[ETH_MAC_LEN];
  uint8_t   station[ETH_MAC_LEN];
  uint8_t   ap[ETH_MAC_LEN];
  uint8_t   channel;
  uint8_t   err;
  signed    rssi;
};


/* ==============================================
   Promiscous callback structures, see ESP manual
   ============================================== */
struct RxControl {
  signed   rssi             :8;  // signal intensity of packet
  unsigned rate             :4;
  unsigned is_group         :1;
  unsigned                  :1;
  unsigned sig_mode         :2;  // 0:is 11n packet; 1:is not 11n packet;
  unsigned legacy_length    :12; // if not 11n packet, shows length of packet.
  unsigned damatch0         :1;
  unsigned damatch1         :1;
  unsigned bssidmatch0      :1;
  unsigned bssidmatch1      :1;
  unsigned MCS              :7;  // if is 11n packet, shows the modulation
                                 // and code used (range from 0 to 76)
  unsigned CWB              :1;  // if is 11n packet, shows if is HT40 packet or not
  unsigned HT_length        :16; // if is 11n packet, shows length of packet.
  unsigned Smoothing        :1;
  unsigned Not_Sounding     :1;
  unsigned                  :1;
  unsigned Aggregation      :1;
  unsigned STBC             :2;
  unsigned FEC_CODING       :1;  // if is 11n packet, shows if is LDPC packet or not.
  unsigned SGI              :1;
  unsigned rxend_state      :8;
  unsigned ampdu_cnt        :8;
  unsigned channel          :4;  // which channel this packet in.
  unsigned                  :12;
};

struct LenSeq {
  uint16_t  length;             // length of packet
  uint16_t  seq;                // serial number of packet, the high 12bits are serial number,
                                // low 14 bits are Fragment number (usually be 0)
  uint8_t   address3[6];        // the third address in packet
};

struct sniffer_buf {
  struct RxControl  rx_ctrl;
  uint8_t           buf[36];    // head of ieee80211 packet
  uint16_t          cnt;        // number count of packet
  struct LenSeq     lenseq[1];  // length of packet
};

struct sniffer_buf2 {
  struct RxControl  rx_ctrl;
  uint8_t           buf[112];
  uint16_t          cnt;        // number count of packet
  uint16_t          len;        // length of packet
};

struct control_frame {
   unsigned int   ver     :2;   // protocol version (should be 0x0)
   unsigned int   type    :2;   // 0x0= Management, 0x1=Control, 0x2=Data
   unsigned int   subtype :4;

} ;
