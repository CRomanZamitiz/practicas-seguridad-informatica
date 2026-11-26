/*
 * Practica de Laboratorio: Sniffer de Red en Capa 2 (Raw Sockets)
 * Version filtrada para demostracion en vivo (solo captura POST /enviar)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <net/if.h>

int main() {
    int raw_socket;
    // +1 byte extra para asegurar terminacion nula ('\0') al buscar con strstr
    unsigned char *buffer = (unsigned char *)malloc(65537);
    if (!buffer) {
        perror("Error al reservar memoria");
        return 1;
    }

    raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_socket < 0) {
        perror("Error al crear el socket (Ejecutaste el programa con sudo?)");
        free(buffer);
        return 1;
    }

    printf(">>> SNIFFER ACTIVO (Modo Demostracion): Escuchando en puerto 8080...\n");
    printf(">>> Filtrando solo mensajes enviados (POST /enviar)...\n");

    while (1) {
        int data_size = recvfrom(raw_socket, buffer, 65536, 0, NULL, NULL);
        if (data_size < 0) {
            continue;
        }

        struct ethhdr *eth = (struct ethhdr *)buffer;

        if (ntohs(eth->h_proto) == ETH_P_IP) {
            struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));

            if (iph->protocol == 6) { // TCP
                unsigned short iphdrlen = iph->ihl * 4;
                struct tcphdr *tcph = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + iphdrlen);

                // Solo trafico entrante al servidor (puerto destino 8080)
                if (ntohs(tcph->dest) == 8080) {
                    int tcp_header_len = tcph->doff * 4;
                    int total_headers_size = sizeof(struct ethhdr) + iphdrlen + tcp_header_len;

                    // Calculo real del payload usando iph->tot_len (ignora padding de Ethernet)
                    int ip_total_len = ntohs(iph->tot_len);
                    int payload_size = ip_total_len - iphdrlen - tcp_header_len;

                    if (payload_size > 0 && (total_headers_size + payload_size) <= data_size) {
                        unsigned char *payload = buffer + total_headers_size;
                        payload[payload_size] = '\0'; // Terminamos cadena de forma segura

                        // Filtramos solo los envios de mensajes del chat (ignora GET /mensajes)
                        if (strstr((char *)payload, "POST /enviar") != NULL ||
                            strstr((char *)payload, "USUARIO=") != NULL) {

                            printf("\n=======================================================");
                            printf("\n---[ MENSAJE INTERCEPTADO EN TEXTO PLANO ]---");
                            printf("\nMAC Origen: %02x:%02x:%02x:%02x:%02x:%02x",
                                   eth->h_source[0], eth->h_source[1], eth->h_source[2],
                                   eth->h_source[3], eth->h_source[4], eth->h_source[5]);
                            printf("\nIP Origen : %s", inet_ntoa(*(struct in_addr *)&iph->saddr));
                            printf("\nPuerto Src: %d -> Puerto Dst: %d", ntohs(tcph->source), ntohs(tcph->dest));
                            printf("\n\nContenido del mensaje (Payload):\n%.*s\n", payload_size, payload);
                            printf("=======================================================\n");
                            fflush(stdout);
                        }
                    }
                }
            }
        }
    }

    free(buffer);
    close(raw_socket);
    return 0;
}
