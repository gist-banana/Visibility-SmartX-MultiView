# url : 127.0.0.1
import plotly.graph_objects as go
import time
from kafka import KafkaConsumer
import sys

bootstrap_servers = ['localhost:9091','localhost:9092','localhost:9090']
topicName = 'xdp_kafka_topic'

consumer = KafkaConsumer (topicName, group_id = 'group1', bootstrap_servers = bootstrap_servers, auto_offset_reset = 'earliest')

test_value1 = 14
test_value2 = 2

mid_val3 = [0,0,0]
# define colors codes here
RED = "#ff0000"
DARK_GREEN = "#224d17"
GREEN = "#099441"
LIGHT_GREEN = "#60a830"
YELLOW_GREEN = "d9df1d"
BLACK = "#000000"
WHITE = "#FFFFFF"
GRAY = "#808080"
SILVER = "C0C0C0"
# define parameter values for coloring

LEVEL0 = 0
LEVEL1 = 10
LEVEL2 = 15
LEVEL3 = 20
LEVEL4 = 25
LEVEL5 = 30
LEVEL6 = 35

# define level colors here

LEVEL0_COL = GRAY
LEVEL1_COL = YELLOW_GREEN
LEVEL2_COL = LIGHT_GREEN
LEVEL3_COL = GREEN
LEVEL4_COL = DARK_GREEN
LEVEL5_COL = RED
        
def kafka_consumer():
    print("Kafka consumer initiating...")
    try :
        for message in consumer:
            value = message.value
#            if (value[0] != '0'):
            print(value)
            print('\n')
    except KeyboardInterrupt:
        sys.exit()

def draw_graph():
    iterator = 0
    print("Kafka consumer initiating...")
    try :
        for message in consumer:
            test_value1 = message.value
            test_value1 = str(test_value1)
#            if (value[0] != '0'):
            print(test_value1)
            print('\n')
            print("Kafka consumer initiaing...")
# from here, disect the packet and the ip address
            
            disector = test_value1.find(' ')

# disector -> address + ' ' + packet/sec
            print('\n')
            print("ip address : ")
            ip_address = test_value1[0:disector]
            print(ip_address)
            print("incoming packets : ")
            packets = test_value1[disector+1:]
            print(packets)
            

# assign color codes here since I believe color assignment should be done for both components all the time
# later for the economy of the code, two paragraphs below can be merged into one using list : {bpf1,bpf2} and iterating it
            if packets == LEVEL0:
                bpf2_color = LEVEL0_COL
            elif LEVEL0 < packets and packets  < LEVEL1 :
                bpf2_color = LEVEL1_COL
            elif LEVEL1 <= packets and packets < LEVEL2 :
                bpf2_color = LEVEL2_COL
            elif LEVEL2 <= packets and packets < LEVEL3 :
                bpf2_color = LEVEL3_COL
            elif LEVEL3 <= packets and packets < LEVEL4 :
                bpf2_color = LEVEL4_COL
            else :
                bpf2_color = LEVEL5_COL

            if test_value2 < LEVEL1 :
                bpf3_color = LEVEL1_COL
            elif LEVEL1 <= test_value2 and test_value2 < LEVEL2 :
                bpf3_color = LEVEL2_COL
            elif LEVEL2 <= test_value2 and test_value2 < LEVEL3 :
                bpf3_color = LEVEL3_COL
            elif LEVEL3 <= test_value2 and test_value2 < LEVEL4 :
                bpf3_color = LEVEL4_COL
            else :
                bpf3_color = LEVEL5_COL

# Each arguments below have to be assigned only a single time. IF NOT -> ERROR
            fig =go.Figure(go.Sunburst(
            labels=[" " ,"Kubernetes Master", "Kubernetes Worker", "DoS Attacker","Ethernet(eno2) ","Netronome(enp4s0np1)","Ethernet(eno2)","Netronome(enp32s0np1","Ethernet(eno1)","Intel(enp6s0f0)"],
# all the settings below probably follows the order of the labels above
	    parents=[""," "," "," ","Kubernetes Master","Kubernetes Master","Kubernetes Worker","Kubernetes Worker","DoS Attacker","DoS Attacker"],
#	    values=[20, 20, 20,20], # size of each components of the graph # this line decides the size of the components on the onion-ring. Leaving this blank will result in equal sizing for every component
# values = [BPF2, BPF3, BPF1] : BFP1 size doesn't really change
	    hoverlabel = {"bordercolor":BLACK}, # sets the border color of mouse over
            marker = {"colors":[WHITE,BLACK,BLACK,BLACK,YELLOW_GREEN,GRAY,YELLOW_GREEN,GRAY,YELLOW_GREEN,GRAY]}, # in the order of BPF2, BPF3
	    hovertext = ['','','','','','','','192.168.1.10'],
	    hoverinfo = ["label+text"],
            ))
            fig.update_layout(margin = dict(t=0, l=0, r=0, b=0))
            go.visible = False
#            if (test_value1 > 50):
            fig.show()
    except KeyboardInterrupt:
        sys.exit()   
 

draw_graph()
#kafka_consumer()
