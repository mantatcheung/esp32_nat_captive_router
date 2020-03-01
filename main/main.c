#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_wpa2.h"
#include "esp_event_loop.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "driver/gpio.h"

//Added by Andrew
#include "esp_spiffs.h"
#include "tcpip_adapter.h"

//Added by Andrew
#define IP_NAPT 1	
#include "lwip/lwip_napt.h"
//#include "lwip/app/dhcpserver.h"
#include "lwip/netif.h"
#include "netif/etharp.h"
#include "lwip/udp.h"

#include "lwip/ip_addr.h"

#include "lwip/prot/ethernet.h"
//#define 	ETH_ADDR(b0, b1, b2, b3, b4, b5)   {{b0, b1, b2, b3, b4, b5}}

#define MAX_CLIENTS 4
const char DHCP_PORT = 67;
const char DNS_PORT = 53;
const char HTTP_PORT = 80;

//IPAddress myIP;
PACK_STRUCT_BEGIN
struct tcp_hdr {
  PACK_STRUCT_FIELD(u16_t src); 
  PACK_STRUCT_FIELD(u16_t dest); 
  PACK_STRUCT_FIELD(u32_t seqno); 
  PACK_STRUCT_FIELD(u32_t ackno); 
  PACK_STRUCT_FIELD(u16_t _hdrlen_rsvd_flags);
  PACK_STRUCT_FIELD(u16_t wnd);
  PACK_STRUCT_FIELD(u16_t chksum);
  PACK_STRUCT_FIELD(u16_t urgp);
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END

// some magic from inside the NAT lwip for address rewriting
//extern "C" {
//  void ip_napt_modify_addr_tcp(struct tcp_hdr *tcphdr, ip_addr_p_t *oldval, u32_t newval);
//  void ip_napt_modify_addr(struct ip_hdr *iphdr, ip_addr_p_t *field, u32_t newval);
//}
void ip_napt_modify_addr_tcp(struct tcp_hdr *tcphdr, ip4_addr_p_t *oldval, u32_t newval);
void ip_napt_modify_addr(struct ip_hdr *iphdr, ip4_addr_p_t *field, u32_t newval);

static netif_input_fn orig_input_ap;
static netif_linkoutput_fn orig_output_ap;
struct eth_addr curr_mac;
uint32_t curr_IP;

struct eth_addr allowed_macs[MAX_CLIENTS]={{{0xbc,0xa9,0x20,0xdd,0x64,0x8f}},{{0x60,0x67,0x20,0x8a,0x91,0x9c}},{{0,0,0,0,0,0}},{{0,0,0,0,0,0}}};
int max_client = 0; //Andrew - should start from 0
//-----------------------

#if IP_NAPT
#include "lwip/lwip_napt.h"
#endif

#include "lwip/err.h"
#include "lwip/sys.h"

#define MY_DNS_IP_ADDR 0x08080808 // 8.8.8.8
#define MY_AP_IP_ADDR 0xC0A80401  // 192.168.4.1

// WIFI CONFIGURATION
#define ESP_AP_SSID "AP32T"
#define ESP_AP_PASS "0000"

#define EXAMPLE_ESP_WIFI_SSID      "ESP_WIFI_SSID"
#define EXAMPLE_ESP_WIFI_PASS      "ESP_WIFI_PASS"

#define EXAMPLE_ESP_MAXIMUM_RETRY  3

/* FreeRTOS event group to signal when we are connected*/
static EventGroupHandle_t s_wifi_event_group;

/* The event group allows multiple bits for each event, but we only care about one event
 * - are we connected to the AP with an IP? */
const int WIFI_CONNECTED_BIT = BIT0;

static const char *TAG = "apsta";

static int s_retry_num = 0;

static esp_err_t event_handler(void *ctx, system_event_t *event)
{
  switch(event->event_id) {
  case SYSTEM_EVENT_STA_START:
    esp_wifi_connect();
    break;
  case SYSTEM_EVENT_STA_GOT_IP:
    ESP_LOGI(TAG, "got ip:%s",
	     ip4addr_ntoa(&event->event_info.got_ip.ip_info.ip));
    s_retry_num = 0;
    xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    break;
  case SYSTEM_EVENT_STA_DISCONNECTED:
    {
//      if (s_retry_num < EXAMPLE_ESP_MAXIMUM_RETRY) {
      if (s_retry_num < 1000) {  //Andrew
      esp_wifi_connect();
        xEventGroupClearBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
        s_retry_num++;
        ESP_LOGI(TAG,"retry to connect to the AP");
      }
      ESP_LOGI(TAG,"connect to the AP failed");
      break;
    }
  case SYSTEM_EVENT_AP_STACONNECTED:
    ESP_LOGI(TAG,"station connected");
    break;
  case SYSTEM_EVENT_AP_STADISCONNECTED:
    ESP_LOGI(TAG,"station disconnected");
    break;
  default:
    break;
  }
  return ESP_OK;
}

void wifi_init_sta()
{
    ip_addr_t dnsserver;
    tcpip_adapter_dns_info_t dnsinfo;

    s_wifi_event_group = xEventGroupCreate();

    tcpip_adapter_init();
    ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL) );

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    /* ESP STATION CONFIG */
    wifi_config_t wifi_config = {
      .sta = {
  	    .ssid = EXAMPLE_ESP_WIFI_SSID,
	      .password = EXAMPLE_ESP_WIFI_PASS
      },
    };

    /* ESP AP CONFIG */
    wifi_config_t ap_config = {
      .ap = {
  	    .ssid = ESP_AP_SSID,
	      .channel = 0,
        .authmode = WIFI_AUTH_OPEN,
//  	    .authmode = WIFI_AUTH_WPA2_PSK,
  	    .password = ESP_AP_PASS,
	      .ssid_hidden = 0,
	      .max_connection = 8,
	      .beacon_interval = 100
    	}
    };

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA) );
    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config) );
    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_AP, &ap_config) );

    // Enable DNS (offer) for dhcp server
    dhcps_offer_t dhcps_dns_value = OFFER_DNS;
    dhcps_set_option_info(6, &dhcps_dns_value, sizeof(dhcps_dns_value));

    // Set custom dns server address for dhcp server
    dnsserver.u_addr.ip4.addr = htonl(MY_DNS_IP_ADDR);
    dnsserver.type = IPADDR_TYPE_V4;
    dhcps_dns_setserver(&dnsserver);

    tcpip_adapter_get_dns_info(TCPIP_ADAPTER_IF_AP, TCPIP_ADAPTER_DNS_MAIN, &dnsinfo);
    ESP_LOGI(TAG, "DNS IP:" IPSTR, IP2STR(&dnsinfo.ip.u_addr.ip4));

    //Set HT40 - Faster?
    if(esp_wifi_set_bandwidth(WIFI_IF_STA, WIFI_BW_HT40)!=ESP_OK)
      ESP_LOGI(TAG, "Set WIFI_IF_STA failed");
  else
      ESP_LOGI(TAG, "Set WIFI_IF_STA success");
  
    if(esp_wifi_set_bandwidth(WIFI_IF_AP, WIFI_BW_HT40)!=ESP_OK)
      ESP_LOGI(TAG, "Set WIFI_IF_AP failed");
  else
      ESP_LOGI(TAG, "Set WIFI_IF_AP success");
  //------------------------------------------  
  
//what is my own AP address?  
  
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "wifi_init_apsta finished.");
    ESP_LOGI(TAG, "connect to ap SSID: %s ", EXAMPLE_ESP_WIFI_SSID);
}

//Added by Andrew
/* Function to initialize SPIFFS */
static esp_err_t init_spiffs(void)
{
    ESP_LOGI(TAG, "Initializing SPIFFS");

    esp_vfs_spiffs_conf_t conf = {
      .base_path = "/spiffs",
      .partition_label = NULL,
      .max_files = 5,   // This decides the maximum number of files that can be created on the storage
      .format_if_mount_failed = true
    };

    esp_err_t ret = esp_vfs_spiffs_register(&conf);
    if (ret != ESP_OK) {
        if (ret == ESP_FAIL) {
            ESP_LOGE(TAG, "Failed to mount or format filesystem");
        } else if (ret == ESP_ERR_NOT_FOUND) {
            ESP_LOGE(TAG, "Failed to find SPIFFS partition");
        } else {
            ESP_LOGE(TAG, "Failed to initialize SPIFFS (%s)", esp_err_to_name(ret));
        }
        return ESP_FAIL;
    }

    size_t total = 0, used = 0;
    ret = esp_spiffs_info(NULL, &total, &used);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to get SPIFFS partition information (%s)", esp_err_to_name(ret));
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Partition size: total: %d, used: %d", total, used);
    return ESP_OK;
}

/* Declare the function which starts the file server.
 * Implementation of this function is to be found in
 * file_server.c */
esp_err_t start_file_server(const char *base_path);

//====================================================================================

//Added by Andrew ====================================================================
bool check_packet_in(struct pbuf *p) {
struct eth_hdr *mac_h;
struct ip_hdr *ip_h;
struct udp_hdr *udp_he;
struct tcp_hdr *tcp_h;
  
  //Added by Andrew
  ESP_LOGI(TAG, "Pkt In");
  //return true;
  //---------------
  
  if (p->len < sizeof(struct eth_hdr))
    return false;

  mac_h = (struct eth_hdr *)p->payload;
  
  // Check only IPv4 traffic
  if (ntohs(mac_h->type) != ETHTYPE_IP)
    return true;

  if (p->len < sizeof(struct eth_hdr)+sizeof(struct ip_hdr))
    return false;

  ip_h = (struct ip_hdr *)(p->payload + sizeof(struct eth_hdr));

  // Known MACs can pass
  for(int i = 0; i<max_client; i++) {
    if (memcmp(mac_h->src.addr, allowed_macs[i].addr, sizeof(mac_h->src.addr)) == 0) {
      return true;
    }
  }

  // DHCP and DNS is okay
  if (IPH_PROTO(ip_h) == IP_PROTO_UDP) {
    if (p->len < sizeof(struct eth_hdr)+sizeof(struct ip_hdr)+sizeof(struct udp_hdr))
      return false;
    
    udp_he = (struct udp_hdr *)(p->payload + sizeof(struct eth_hdr) + sizeof(struct ip_hdr));

    if (ntohs(udp_he->dest) == DHCP_PORT)
      return true;

    if (ntohs(udp_he->dest) == DNS_PORT)
      return true;

    ESP_LOGI(TAG, "Pkt Dropped#1");
    return false;
  }

  //HTTP is redirected  
  if (IPH_PROTO(ip_h) == IP_PROTO_TCP) {
    if (p->len < sizeof(struct eth_hdr)+sizeof(struct ip_hdr)+sizeof(struct tcp_hdr))
      return false;
      
    tcp_h = (struct tcp_hdr *)(p->payload + sizeof(struct eth_hdr) + sizeof(struct ip_hdr));
    
    if (ntohs(tcp_h->dest) == HTTP_PORT) {
      curr_mac = mac_h->src;
      curr_IP = ip_h->dest.addr;
      
      ESP_LOGI(TAG, "Pkt In ip_h->dest.addr=%x", curr_IP);

      ip_napt_modify_addr_tcp(tcp_h, (ip4_addr_p_t *)&ip_h->dest, (uint32_t)0x104A8C0);
      ip_napt_modify_addr(ip_h, (ip4_addr_p_t *)&ip_h->dest, (uint32_t)0x104A8C0);      

      ESP_LOGI(TAG, "Pkt In Redirected");
      return true;
    }
   //ESP_LOGI(TAG, "Pkt In Force Allowed");
   //return true;   
  }
    

  // drop anything else
    ESP_LOGI(TAG, "Pkt Dropped#2");
    return false;
}

err_t my_input_ap (struct pbuf *p, struct netif *inp) {

  if (check_packet_in(p)) {
    return orig_input_ap(p, inp);
  } else {
    pbuf_free(p);
    return ERR_OK; 
  }
}

bool check_packet_out(struct pbuf *p) {
struct eth_hdr *mac_h;
struct ip_hdr *ip_h;
struct tcp_hdr *tcp_h;
  
  //Added by Andrew
  //return true;
  //Added by Andrew
  ESP_LOGI(TAG, "Pkt Out");
  //---------------
  
  
  if (p->len < sizeof(struct eth_hdr)+sizeof(struct ip_hdr)+sizeof(struct tcp_hdr))
    return true;

  ip_h = (struct ip_hdr *)(p->payload + sizeof(struct eth_hdr));

  if (IPH_PROTO(ip_h) != IP_PROTO_TCP)
    return true;
    
  tcp_h = (struct tcp_hdr *)(p->payload + sizeof(struct eth_hdr) + sizeof(struct ip_hdr));

  
  // rewrite packet from our HTTP server 
  if (ntohs(tcp_h->src) == HTTP_PORT && ip_h->src.addr == (uint32_t)0x104A8C0) {
  ip_napt_modify_addr_tcp(tcp_h, (ip4_addr_p_t *)&ip_h->src, curr_IP);
    ip_napt_modify_addr(ip_h, (ip4_addr_p_t *)&ip_h->src, curr_IP);
    ESP_LOGI(TAG, "Pkt Out Redirected");
  }
    
  return true;
}

err_t my_output_ap (struct netif *outp, struct pbuf *p) {

  if (check_packet_out(p)) {
    return orig_output_ap(outp, p);
  } else {
    pbuf_free(p);
    return ERR_OK; 
  }
}

// patches the netif to insert the filter functions
void patch_netif(ip_addr_t netif_ip, netif_input_fn ifn, netif_input_fn *orig_ifn, netif_linkoutput_fn ofn, netif_linkoutput_fn *orig_ofn)
{
  //struct netif *nif;  //original
  struct netif *nif=NULL; //By Andrew

  ESP_LOGI(TAG, "patch_netif: started");
  
  //for (nif = netif_list; nif != NULL && nif->ip_addr.addr != netif_ip.addr; nif = nif->next); //Original
  for (nif = netif_list; nif != NULL && nif->ip_addr.u_addr.ip4.addr != netif_ip.u_addr.ip4.addr; nif = nif->next); // By Andrew

  if (nif == NULL) return;

  if (ifn != NULL && nif->input != ifn) {
    *orig_ifn = nif->input;
    nif->input = ifn;
  }
  if (ofn != NULL && nif->linkoutput != ofn) {
    *orig_ofn = nif->linkoutput;
    nif->linkoutput = ofn;
  }
}
//---------------

void app_main()
{
  // Initialize NVS
  esp_err_t ret = nvs_flash_init();
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    ret = nvs_flash_init();
  }
  ESP_ERROR_CHECK(ret);

  // Copied from file server example
  //tcpip_adapter_init();
  //ESP_ERROR_CHECK(esp_event_loop_create_default());
  
  // Setup WIFI
  wifi_init_sta();

#if IP_NAPT  
   // Insert the filter functions
  vTaskDelay(5000/ portTICK_PERIOD_MS);
  ip_addr_t AP_Addr;
  AP_Addr.u_addr.ip4.addr = htonl(MY_AP_IP_ADDR);
  AP_Addr.type = IPADDR_TYPE_V4;
  patch_netif(AP_Addr, my_input_ap, &orig_input_ap, my_output_ap, &orig_output_ap);
  
  // Setup MAC Address for Testing
  //ETHADDR32_COPY(allowed_macs[0],{{0xbc,0xa9,0x20,0xdd,0x64,0x8f}});
  //struct eth_addr allowed_macs[MAX_CLIENTS];
  
    
  u32_t napt_netif_ip = 0xC0A80401; // Set to ip address of softAP netif (Default is 192.168.4.1)
  ip_napt_enable(htonl(napt_netif_ip), 1);
  ESP_LOGI(TAG, "NAT is enabled");
#endif

  /* Initialize file storage */
  ESP_ERROR_CHECK(init_spiffs());

  /* Start the file server */
  ESP_ERROR_CHECK(start_file_server("/spiffs"));
  
}
