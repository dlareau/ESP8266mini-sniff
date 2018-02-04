//parse out details of client frame
struct clientinfo parse_data(struct sniffer_buf *sniffer, uint16_t framelen)
{
  // takes 36 byte frame control frame
  struct clientinfo ci;
  uint8_t *frame = sniffer->buf;
  ci.channel = sniffer->rx_ctrl.channel;
  ci.err = 0;
  ci.rssi = sniffer->rx_ctrl.rssi;
  uint8_t *bssid;
  uint8_t *station;
  uint8_t *ap;
  uint8_t ds;
  ds = frame[1] & 3;    //Set first 6 bits to 0
  switch (ds) {
    // p[1] - xxxx xx00 => NoDS   p[4]-DST p[10]-SRC p[16]-BSS
    case 0:
      bssid = frame + 16;
      station = frame + 10;
      ap = frame + 4;
      break;
    // p[1] - xxxx xx01 => ToDS   p[4]-BSS p[10]-SRC p[16]-DST
    case 1:
      bssid = frame + 4;
      station = frame + 10;
      ap = frame + 16;
      break;
    // p[1] - xxxx xx10 => FromDS p[4]-DST p[10]-BSS p[16]-SRC
    case 2:
      bssid = frame + 10;
      // hack - don't know why it works like this...
      if (memcmp(frame + 4, broadcast1, 3) || memcmp(frame + 4, broadcast2, 3) || memcmp(frame + 4, broadcast3, 3)) {
        station = frame + 16;
        ap = frame + 4;
      } else {
        station = frame + 4;
        ap = frame + 16;
      }
      break;
    // p[1] - xxxx xx11 => WDS    p[4]-RCV p[10]-TRM p[16]-DST p[26]-SRC
    case 3:
      bssid = frame + 10;
      station = frame + 4;
      ap = frame + 4;
      break;
  }

  memcpy(ci.station, station, ETH_MAC_LEN);
  memcpy(ci.bssid, bssid, ETH_MAC_LEN);
  memcpy(ci.ap, ap, ETH_MAC_LEN);

  return ci;
}



struct beaconinfo parse_beacon(struct sniffer_buf2 *sniffer, uint16_t framelen)
{
  // takes 112 byte beacon frame
  struct beaconinfo bi;
  uint8_t *frame = sniffer->buf;
  bi.ssid_len = 0;
  bi.channel = sniffer->rx_ctrl.channel;
  bi.err = 0;
  bi.rssi = sniffer->rx_ctrl.rssi;
  int pos = 36;
  uint8_t frame_type= (frame[0] & 0x0C)>>2;
  uint8_t frame_subtype= (frame[0] & 0xF0)>>4;
  if (frame[pos] == 0x00) {
    bi.ssid_len = (int) frame[pos + 1];
    if (bi.ssid_len == 0) {
      memset(bi.ssid, '\x00', 33);
    }else if (bi.ssid_len < 0) {
      bi.err = -1;
    } else if (bi.ssid_len > 32) {
      bi.err = -2;
    }
    memset(bi.ssid, '\x00', 33);
    memcpy(bi.ssid, frame + pos + 2, bi.ssid_len);
    bi.err = 0;  // before was error??
  } else {
    bi.err = -3;
  }

  memcpy(bi.mac_addr, frame + 10, ETH_MAC_LEN);
  return bi;
};

struct probeinfo parse_probe(struct sniffer_buf2 *sniffer, uint16_t framelen)
{
  // takes 112 byte probe request frame
  struct probeinfo pi;
  uint8_t *frame = sniffer->buf;
  pi.ssid_len = 0;
  pi.channel = sniffer->rx_ctrl.channel;
  pi.err = 0;
  pi.rssi = sniffer->rx_ctrl.rssi;
  int pos = 24;
  uint8_t frame_type= (frame[0] & 0x0C)>>2;
  uint8_t frame_subtype= (frame[0] & 0xF0)>>4;
   
  if (frame[pos] == 0x00) {
    pi.ssid_len = (int) frame[pos + 1];
    if (pi.ssid_len == 0) {
      memset(pi.ssid, '\x00', 33);
    }
    if (pi.ssid_len < 0) {
      pi.err = -1;
    }
    if (pi.ssid_len > 32) {
      pi.err = -2;
    }
    memset(pi.ssid, '\x00', 33);
    memcpy(pi.ssid, frame + pos + 2, pi.ssid_len);
    pi.err = 0;  // before was error??
  } else {
    pi.err = -3;
  }

  memcpy(pi.mac_addr, frame+10, ETH_MAC_LEN);
  return pi;
}


int register_beacon(beaconinfo beacon)
{
  // add beacon to list if not already included
  int known = 0;   // Clear known flag
  for (int u = 0; u < aps_known_count; u++)
  {
    if (! memcmp(aps_known[u].mac_addr, beacon.mac_addr, ETH_MAC_LEN)) {
      known = 1;
      break;
    }   // AP known => Set known flag
  }
  if (! known)  // AP is NEW, copy MAC to array and return it
  {
    memcpy(&aps_known[aps_known_count], &beacon, sizeof(beacon));
    aps_known_count++;

    if ((unsigned int) aps_known_count >=
        sizeof (aps_known) / sizeof (aps_known[0]) ) {
      Serial.printf("exceeded max aps_known\n");
      aps_known_count = 0;
    }
  }
  return known;
}

int register_client(clientinfo ci)
{
  // add client to list if not already included
  int known = 0;   // Clear known flag
  for (int u = 0; u < clients_known_count; u++)
  {
    if ((! memcmp(clients_known[u].station, ci.station, ETH_MAC_LEN)) &&
        (! memcmp(clients_known[u].bssid, ci. bssid, ETH_MAC_LEN))){
      known = 1;
      break;
    }
  }
  if (! known)
  {
    memcpy(&clients_known[clients_known_count], &ci, sizeof(ci));
    clients_known_count++;

    if ((unsigned int) clients_known_count >=
        sizeof (clients_known) / sizeof (clients_known[0]) ) {
      Serial.printf("exceeded max clients_known\n");
      clients_known_count = 0;
    }
  }
  return known;
}

int register_probe(probeinfo pi)
{
  //add probe to list if not already included.
  int known = 0;   // Clear known flag
  for (int u = 0; u < probes_known_count; u++)
  {
    if ((memcmp(probes_known[u].mac_addr, pi.mac_addr, ETH_MAC_LEN) == 0)
       && (strncmp((char*)probes_known[u].ssid, (char*)pi.ssid, sizeof(pi.ssid)) == 0 )) {
      known = 1;
      break;
    }
  }
  if (! known)
  {
    memcpy(&probes_known[probes_known_count], &pi, sizeof(pi));
    probes_known_count++;

    if ((unsigned int) probes_known_count >=
        sizeof (probes_known) / sizeof (probes_known[0]) ) {
      Serial.printf("exceeded max probes_known\n");
      probes_known_count = 0;
    }
  }
  return known;
}

void print_beacon(beaconinfo beacon)
{
  uint64_t now = millis()/1000;
  if (beacon.err != 0) {
    Serial.printf("BEACON ERR: (%d)  \r\n", beacon.err);
  } else {
    Serial.printf("BEACON: <=============== [%32s]  ", beacon.ssid);
    for (int i = 0; i < 6; i++) Serial.printf("%02x", beacon.mac_addr[i]);
    Serial.printf(" %3d", beacon.channel);
    Serial.printf("   %4d\r\n", beacon.rssi);

  }
}

void print_client(clientinfo ci)
{
  int u = 0;
  int known = 0;   // Clear known flag
  uint64_t now = millis()/1000;
  if (ci.err != 0) {
    Serial.printf("ci.err %02d", ci.err);
    Serial.printf("\r\n");
  } else {
    Serial.printf("DEVICE: ");
    for (int i = 0; i < 6; i++) Serial.printf("%02x", ci.station[i]);
    Serial.printf(" ==> ");

    for (u = 0; u < aps_known_count; u++)
    {
      if (! memcmp(aps_known[u].mac_addr, ci.bssid, ETH_MAC_LEN)) {
        Serial.printf("[%32s]  ", aps_known[u].ssid);
        known = 1;     // AP known => Set known flag
        break;
      }
    }

    if (! known)  {
      Serial.printf("[%32s]  ", "??");    
    };
    for (int i = 0; i < 6; i++) Serial.printf("%02x", ci.bssid[i]);
    Serial.printf(" %3d", ci.channel);
    Serial.printf("   %4d\r\n", ci.rssi);
  }
}

void print_probe(probeinfo pi)
{
  int u = 0;
  int known = 0;   // Clear known flag
  uint64_t now = millis()/1000;
  if (pi.err != 0) {
    Serial.printf("pi.err %02d", pi.err);
    Serial.printf("\r\n");
  } else {
    Serial.printf("PROBE:  ");
    for (int i = 0; i < 6; i++) Serial.printf("%02x", pi.mac_addr[i]);
    Serial.printf(" ==> ");
    Serial.printf("[%32s]  ", pi.ssid);
    for (int i = 0; i < 6; i++) Serial.printf("%02x", broadcast2[i]);
    Serial.printf(" %3d", pi.channel);
    Serial.printf("   %4d\r\n", pi.rssi);
  }
};


void print_pkt_header(uint8_t *buf, uint16_t len, char *pkt_type)
{
  char ssid_name[33];
  memset(ssid_name, '\x00', 33);
  Serial.printf("%s", pkt_type);
  uint8_t frame_control_pkt = buf[12]; // just after the RxControl Structure
  uint8_t protocol_version = frame_control_pkt & 0x03; // should always be 0x00
  uint8_t frame_type = (frame_control_pkt & 0x0C) >> 2;
  uint8_t frame_subtype = (frame_control_pkt & 0xF0) >> 4;
  uint8_t ds= buf[13] & 0x3;
  
  // print the 3 MAC-address fields
  Serial.printf("%02x %02x %02x ", frame_type, frame_subtype, ds);
  if (len<35) {
    Serial.printf("Short Packet!! %d\r\n",len);
    return;
  }
  for (int n = 16; n < 22; n++) {
    Serial.printf("%02x", buf[n]);
  };
  Serial.print(" ");
  for (int n = 22; n < 28; n++) {
    Serial.printf("%02x", buf[n]);
  };
  Serial.print(" ");
  for (int n = 28; n < 34; n++) {
    Serial.printf("%02x", buf[n]);
  };
  //ACTION frames are 112 long but contain nothing useful
  if (len>=112 && !( frame_type==0 && frame_subtype==13)) {
    
    int pos=49;
    if (frame_type==0 && frame_subtype==4) {
      pos=37; // probe request frames
    }
    
    int bssid_len=(int) buf[pos];
    if(bssid_len<0 || bssid_len>32) {
      Serial.printf(" Bad ssid len %d!!\r\n",bssid_len);
      return;
    };
    if (bssid_len==0) {
      Serial.print(" <open>");
    } else {
      memcpy(ssid_name,&(buf[pos+1]),bssid_len);
      Serial.printf(" %s",ssid_name);
    };
    Serial.printf(":%d %d %d ",(int)buf[pos+bssid_len+1],(int)buf[pos+bssid_len+2],(int)buf[pos+bssid_len+3]);
  
  };
  Serial.print("\r\n");
}

void promisc_cb(uint8_t *buf, uint16_t len)
{
  if (len < 12) {
    return;
  }

  struct control_frame *cf=(struct control_frame *)&buf[12];

  if (len == 128) {
    struct sniffer_buf2 *sniffer = (struct sniffer_buf2*) buf;

    if (cf->type == 0 && (cf->subtype == 8 || cf->subtype == 5)) {
      struct beaconinfo beacon = parse_beacon(sniffer, 112);

      if (register_beacon(beacon) == 0) {
        print_beacon(beacon);
        nothing_new = 0;
      }
    } else if (cf->type ==0 && cf->subtype==4) {
      struct probeinfo probe = parse_probe(sniffer, 112);

      if (register_probe(probe) == 0) {
        print_probe(probe);
        nothing_new = 0;
      }
    } else {
      print_pkt_header(buf,112,"UKNOWN:");
    }
  } else {
    struct sniffer_buf *sniffer = (struct sniffer_buf*) buf;
    struct clientinfo ci = parse_data(sniffer, 36);

    if (!(cf->type == 1 && (cf->subtype==9 || cf->subtype==8))){
      if (register_client(ci) == 0) {
        print_client(ci);
        nothing_new = 0;
      }
    }
  }
}

