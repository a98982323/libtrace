#include "libtrace.h"
#include <stdio.h>
#include <inttypes.h>
#include <assert.h>
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h> // atoi
uint64_t pkt_ct = 1;
uint32_t obs_interval = 0;
uint32_t obs_time = 100;


typedef struct Pkt_info
{
        double iat;
        struct Pkt_info *next;
}Pkt_info;

Pkt_info *head  = NULL;

void insert_pkt_info(double iat){
        Pkt_info *newPacket =(Pkt_info *)malloc(sizeof(Pkt_info));
        if (newPacket == NULL){
                printf("Mem allocation failed\n");
                exit(1);
        }
        newPacket -> iat = iat;
        newPacket -> next = head;
        head = newPacket;
}

void free_pkt_list(){
        Pkt_info *current = head;
        while (current != NULL)
        {
                Pkt_info *temp =current;
                current = current -> next;
                free(temp);
        }
        
}

static void per_packet(libtrace_packet_t *packet)
{
        // static uint64_t pre_pkt_ts = {0};
        static struct timeval pre_pkt_ts = {0};
        struct  timeval ts;
        // float current_timestamp;
        double current_timestamp;
        // uint32_t iat = 0;
        double iat = 0.0;

        ts = trace_get_timeval(packet);

        if (pre_pkt_ts.tv_sec != 0 || pre_pkt_ts.tv_usec != 0){
                // iat = (ts.tv_sec - pre_pkt_ts.tv_sec) * 1000000 + (ts.tv_usec - pre_pkt_ts.tv_usec);
                iat = (double)(ts.tv_sec - pre_pkt_ts.tv_sec) + (double)(ts.tv_usec - pre_pkt_ts.tv_usec)/1000000.0;
        }

        current_timestamp = (double)ts.tv_sec + (double)ts.tv_usec/ 1000000.0;
        pre_pkt_ts = ts;
        insert_pkt_info(iat);

        if (obs_interval == 0){
                obs_interval = ts.tv_sec + 10;
                printf("Time\t\tPackets\n");
        }
        while ((uint32_t)ts.tv_sec > obs_interval){
                printf("%0.6f\n", current_timestamp);
                printf("%ld.%06ld %llu\n", ts.tv_sec, ts.tv_usec, pkt_ct);
                printf("-----------------------------------------------------------------\n");
                pkt_ct = 0;
                obs_interval += obs_time;
        }
        pkt_ct += 1;
}

static void libtrace_cleanup(libtrace_t *trace, libtrace_packet_t *packet) {

        /* It's very important to ensure that we aren't trying to destroy
         * a NULL structure, so each of the destroy calls will only occur
         * if the structure exists */
        if (trace)
                trace_destroy(trace);

        if (packet)
                trace_destroy_packet(packet);

}


void writeCSV(const char *filename){
        FILE *csvFile = fopen(filename, "w");
        if (csvFile == NULL){
                printf("Error opening file\n");
                exit(1);
        }
        fprintf(csvFile, "IAT\n");

        Pkt_info *current = head;
        while(current!= NULL){
                
                // fprintf(csvFile, "%" PRIu32 ",%u\n", current->iat);
                fprintf(csvFile, "%f\n", current->iat);

                current = current -> next;
        }
        fclose(csvFile);
}
int main(int argc, char *argv[])
{
        /* This is essentially the same main function from readdemo.c */

        libtrace_t *trace = NULL;
        libtrace_packet_t *packet = NULL;

            /* Ensure we have at least one argument after the program name */
        if (argc < 4) {
                fprintf(stderr, "Usage: %s inputURI, interval time, outCSV \n", argv[0]);
        return 1;
        }
        obs_time = atoi(argv[2]);
        packet = trace_create_packet();

        if (packet == NULL) {
                perror("Creating libtrace packet");
                libtrace_cleanup(trace, packet);
                return 1;
        }

        trace = trace_create(argv[1]);

        if (trace_is_err(trace)) {
                trace_perror(trace,"Opening trace file");
                libtrace_cleanup(trace, packet);
                return 1;
        }

        if (trace_start(trace) == -1) {
                trace_perror(trace,"Starting trace");
                libtrace_cleanup(trace, packet);
                return 1;
        }


        while (trace_read_packet(trace,packet)>0) {
                per_packet(packet);
        }


        if (trace_is_err(trace)) {
                trace_perror(trace,"Reading packets");
                libtrace_cleanup(trace, packet);
                return 1;
        }

        printf("%u \t%" PRIu64 "\n", obs_interval, pkt_ct);
        writeCSV(argv[3]);
        
        free_pkt_list();
        libtrace_cleanup(trace, packet);
        return 0;

}

