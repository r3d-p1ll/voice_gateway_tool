from tkinter import *
from tkinter import filedialog
import tkinter


# CREATING THE APPLICATION CLASS FOR THE REAL-TIME SEARCH TOOL AND ITS FUNCTIONALITY

class Application(Frame):

    def __init__(self, master=None):
        Frame.__init__(self, master)

        # SETTING THE VARIABLE FOR THE SEARCH BOX

        self.search_var = StringVar()
        self.switch = False
        self.search_mem = ''

        self.pack()
        self.create_search_box()

    def create_search_box(self):

        # CREATE THE TEXT SEARCH FIELD FOR CONFIGURATION

        self.entry = Entry(self, textvariable=self.search_var, width=25)
        self.listbox1 = Listbox(self, width=35, height=6)
        self.entry.pack()
        self.listbox1.pack()

        # FUNCTION TO UPDATE THE LISTBOX SEARCH - NEEDS TO BE CALLED HERE TO POPULATE THE LISTBOX REAL TIME
        self.update_list()

        self.search_real_time()

    def search_real_time(self):
        # GET THE VALUE OF THE ENTRY BOX
        self.search = self.search_var.get()
        if self.search != self.search_mem:
            self.update_list(is_contact_search=True)

            # SETTING A SWITCH AND SEARCHING THE MEMORY
            self.switch = True
            self.search_mem = self.search

        # IF self.search RETURNS TO '' AFTER PERFORMING SEARCH
        # IT NEEDS TO RESET THE CONTENTS OF THE LIST BOX.
        # A switch IS BEING USED TO DETERMINE WHEN IT NEEDS OT BE UPDATED>


        # RUNS EVERY 50 MILLISECONDS
        if self.switch == True and self.search == '':
            self.update_list()
            self.switch = False
        self.after(50, self.search_real_time)

    def update_list(self, **kwargs):
        try:
            is_contact_search = kwargs['is_contact_search']
        except:
            is_contact_search = False

        # A GENERIC LIST TO POPULATE THE LISTBOX

        self.listbox1.delete(0, END)
        self.listbox1.bind('<ButtonRelease-1>', self.get_list)

        for item in choices:
            if is_contact_search == True:

                # SEARCHES CONTENTS OF lbox_list AND ONLY INSERTS THE ITEM TO THE LIST IF IT self.search IS IN THE CURRENT ITEM.

                if self.search.lower() in item.lower():
                    self.listbox1.insert(END, item)

            else:
                self.listbox1.insert(END, item)

    def get_list(self, event):
        # THIS FUNCTION READS THE LISTBOX SELECTION AND PUTS THE RESULT IN THE ENTRY WIDGET

        # GET SELECTED LINE INDEX

        self.index = self.listbox1.curselection()[:]
        sf = "Example configuration for %s" % self.listbox1.get(self.index)
        root.title(sf)

        # GET THE TEXT OF THE LINE

        user_choice = self.listbox1.get(self.index)

        if user_choice == "SIP Trunk with CUCM":
            SIP_TRUNK_config = """

            SIP TRUNK WITH CUCM

            allow-connections h323 to sip
            allow-connections sip to h323
            allow-connections sip to sip 
            sip
            bind control source-interface Loopback0
            bind media source-interface Loopback0

            "You'd also need to add some sip dial-peers"

            dial-peer voice 1 voip
            destination pattern .T
            session target 12.63.102.3
            session protocol sipv2
            dtmf-relay sip-notify rtp-nte
            codec g711ulaw
            no vad
            
            
            """
            T.insert(END, SIP_TRUNK_config)

        elif user_choice == "Register SCCP Gateway in CUCM":
            SCCP_Gateway = """

            CONFIG SCCP GATEWAY ON CUCM (CME CONFIG)

            conf t 
            sccp local GigabitEthernet0/0
            sccp ccm 10.122.148.47 (the CUCM address) identifier 2 priority 1 version 7.0
            sccp
            sccp ccm group 2
             bind interface GigabitEthernet0/0
             associate ccm 2 priority 1
            stcapp ccm-group 2
            stcapp

            dial-peer voice 7 pots
            service stcapp 
            port 0/2/0 

            voice-port 0/2/0 
            no shut 
            caller-id enable 


            """
            T.insert(END, SCCP_Gateway)

        elif user_choice == "H323 Gateway (with CUCM)":
            H323_Gateway = """

            CONFIGURE H323 ON CME 

            conf t
            voice service voip
             allow-connections h323 to sip
             allow-connections sip to h323
             h323

            interface gigabitEthernet 0/0
            h323-gateway voip bind srcaddr 10.122.148.27  "(if more than 1 interface)"
            h323-gateway voip interface  "(if more than 1 interface)"

            dial-peer voice 5 voip
            destination-pattern ......
            session-target ipv4:......
            voice class h323 1 
            dtmf-relay h245-alphanumeric
            codec g711ulaw 
            no vad

            "optional"
            
            voice service voip 
            h323
            h225 display-ie ccm-compatible 
            exit
            exit
            voice class h323 1
            call start slow/fast 
            telephony-service ccm-compatible 
            
            

            """
            T.insert(END, H323_Gateway)

        elif user_choice == "SIP CME":
            SIP_CME = """

            CME CONFIG FOR SIP
            
            voice service voip 
            allow-connections h323 to sip
            allow-connections sip to h323
            allow-connections sip to sip 
            sip
            bind control source-interface Loopback0
            bind media source-interface Loopback0
            registrar server expires max 120 min 60   !!!
            voice class codec 1 <optional>
            codec preference 1 g711ulaw <optional>
            codec preference 2 g729r8 <optional>
            voice register global 
            mode cme
            source-address <Router's interface>.... port 5060
            max-dn 10
            max-pool 10
            authenticate register
            time-format 24
            date-format D/M/Y
            voice register dn 1
            number 1000
            voice register pool 1
            id mac ......
            type ....
            number 1 dn 1
            voice-class codec 1
            username ... password ... 


            """
            T.insert(END, SIP_CME)

        elif user_choice == "SCCP CME":
            CME_SCCP = """

            CME CONFIG - SCCP

            telephony-service
            no auto-reg-ephone 
            load 7912 <Firmware filename>
            max-ephones 10 
            max-dn 10  
            ip source-address <Router's interface>.... port 2000   - "Which is going to be the CME address and port (loopback address is better)"
            auto assign 1 to 10  "(extra command for phones to be assigned automatically - can be security risk)"
            cnf-file perphone
            create cnf-files version-stamp 7960 sep 27 2006  

            conf t
            ephone-dn 1 dual-line
            number 1000 
            
            ephone 1
            type 7975
            mac-address ....
            button 1:1 


            """
            T.insert(END, CME_SCCP)

        elif user_choice == "Gatekeeper Configuration":
            Gatekeeper_Config = """


            BASIC GATEKEEPER CONFIG - UNICAST, MULTICAST 
            
            "On GW side"

            conf t  
            voice service voip
            allow-connections h323 to h323
            allow-connections h323 to sip
            allow-connections sip to h323

            interface gigabitEthernet 0/0
            ip address .... ....
            h323-gateway voip interface
            h323-gateway voip id gk1 ipaddr ;....
            h323-gateway voip h323-id gw1 

            interface gigabitEthernet 0/0
            ip address .... ....
            h323-gateway voip interface
            h323-gateway voip id gk1 multicast 
            h323-gateway voip h323-id gw1 

            "On GK side"
            
            conf t
            gatekeeper 
            zone local <name> <domain name> 10.122.148.20 
            no shut 


            """
            T.insert(END, Gatekeeper_Config)

        elif user_choice == "Embedded Packet Capture":
            Embedded_P_Cap = """

            EMBEDDED-PACKET-CAPTURE

            MS-2901#monitor capture buffer capture-buff size 4000 max-size 1500 linear
            MS-2901#monitor capture point ip cef capture-pt gigabitEthernet 0/1 both
            MS-2901#monitor capture point associate capture-pt capture-buff
            MS-2901#monitor capture point start all
            MS-2901#monitor capture point stop all
            MS-2901#monitor capture buffer capture-buff export tftp://10.137.8.185/capture.pcap


            """
            T.insert(END, Embedded_P_Cap)

        elif user_choice == "Packet Capture":
            Router_P_Cap = """

            PACKET Capture

            ip traffic-export profile capture mode capture
            bidirectional

            interface gigabitEthernet 0/0
            ip traffic-export apply capture
            exit
            traffic-export interface gigabitethernet 0/0 start 
            show ip traffic-export 
            traffic-export interface gigabitethernet 0/0 stop 
            traffic-export interface gigabitethernet 0/0 copy [flash:filename.cap | ftp://user:pass@10.1.1.1filename.cap]
            dir flash:/CAPTURE1.CAP
            #copy flash0:/CAPTURE1.CAP tftp:


            """
            T.insert(END, Router_P_Cap)

        elif user_choice == "Packet Capture on Processor level":
            Processor_Capture = """

            COLLECT A PACKET CAPTURE ON A PROCESSOR LEVEL 

            conf t
            ip access-list extended CAP-FILTER
            permit ip any any
            exit
            exit

            monitor capture buffer CAP-BUF size 10240 max-size 1514
            monitor capture buffer CAP-BUF filter access-list CAP-FILTER
            monitor capture point ip process-switched CAP-POINT both
            monitor capture point associate CAP-POINT CAP-BUF

            monitor capture point start CAP-POINT
            monitor capture point stop CAP-POINT
            monitor capture buffer CAP-BUF export flash:BUF.pcap


            """
            T.insert(END, Processor_Capture)

        elif user_choice == "PCM Capture":
            PCM_Cap = """

            FOR IOS PRIOR TO 15.2(2)T1

            voice hpi capture buffer 100000
            voice hpi capture destination flash:pcm.dat  - "(On some IOS versions the PCM capture will start immediately after configuring this command)"

            test voice port 0/0/0:23.1 pcm-dump cap 7 duration 255

            TO STOP THE CAPTURE

            no voice hpi capture destination flash:pcm.dat
            no voice hpi capture buffer 100000


            FOR IOS 15.2(2)T1 AND LATER

            voice pcm capture buffer 200000 
            voice pcm capture destination flash:

            test voice port 0/0/0:23.1 pcm-dump caplog fff 


            OR INSTEAD OF COLLECTING ON A PORT, YOU CAN USE A DIAL-PEER

            dial-peer voice x voip/pots
             pcm-dump caplog fff duration xxx

            TO STOP THE PCM CAPTURE

            no voice pcm capture buffer 200000
            no voice pcm capture destination flash:


            """
            T.insert(END, PCM_Cap)

        elif user_choice == "Triggered PCM Capture":
            triggered_PCM = """

            HOW TO COLLECT A TRIGGERED PCM CAPTURE

            "Trigger the PCM Capture when the DTMF key *** on a cisco registered phone. ### is used to stop the capture. (doesn't work always)"
            
            voice pcm capture buffer 200000
            voice pcm capture destination tftp://x.x.x.x/ or flash:
            voice pcm capture on-demand trigger
            voice pcm capture user-trigger-string *** ### stream 7 duration 0


            """
            T.insert(END, triggered_PCM)


        elif user_choice == "Standard ISDN Configuration":
            ISDN_Config = """

            ISDN CONFIGURATION

            conf t
            card type {t1 | e1} 0 0
            network-clock-participate wic 0   - "(Tells the router which module will participate in the clocking)"
            network-clock-select 1 (t1 | e1) <controller slot numb>  - "Configure this only when the Telco provides the clocking to our end.)"
            controller (t1 | e1) 
            clock source (line | internal) -  "(Line - when the Telco provides the clocking to our end; Internal - when we provide the clocking to the other end)"
            linecode (ami | b8zs)  -  "(For most part already configured to b8zs)"
            framing (esf | sf)   -  "(For most part already configured  to esf)"
            isdn switch-type primary-ni
            isdn bchan-number-order descending  - "(Change the B channel order  (default is descending))"
            controller t1 0/0/0 
            pri-group timeslots 1-24  

            conf t 
            serial 0/0/0:23
            isdn protocol emulate user  -  "(When the Telco provides the clocking to us. Configure "network" when we provide clocking.)"
            isdn busy b_channel <number>  -  "(To busy out random channels)"


            """
            T.insert(END, ISDN_Config)

        elif user_choice == "MGCP E1 Configuration":
            MGCP_COnfig_E1 = """

            MGCP CONFIGURATION - E1 

            mgcp call-agent 10.122.148.47 service-type mgcp version 0.1
            mgcp bind control source-interface gigabitEthernet 0/0
            mgcp bind media source-interface gigabitEthernet 0/0

            CCM config for MGCP 

            ccm-manager music-on-hold
            ccm-manager fallback-mgcp
            ccm-manager mgcp
            no ccm-manager fax protocol cisco
            ccm-manager config server 10.122.148.47
            ccm-manager redundant-host <secondary CUCM IP> <Third CUCM IP>
            ccm-manager config

            "Controller config for MGCP"

            conf t
            controller e1 0/0/0
            framing crc4 
            linecode ami
            pri-group timeslots 1-31 service mgcp 

            interface Serial0/0/0:15
             no ip address
             encapsulation hdlc
             isdn switch-type primary-ni
             isdn incoming-voice voice
             isdn bind-l3 ccm-manager  - "(For backhaul)"   
             isdn map address 99261111 plan isdn type national
             isdn bchan-number-order ascending
             no cdp enable


             """
            T.insert(END, MGCP_COnfig_E1)

        elif user_choice == "T1 CAS Configuration":
            CAS_Config = """

            CAS CONFIGURATION
            
            "No serial interface needed"

            controller (t1 | e1) <controller slot num>
            clock source (line | internal)
            linecode
            framing
            ds0-group 1 timeslots 1-3, 4-32 type ? 
            shut 
            no shut  


            """
            T.insert(END, CAS_Config)

        elif user_choice == "PRI/ISDN Shutdown Bug (errors on interface)":
            PRI_ISDN_shutdown = """

            PRI/ISDN SHUTDOWN OR MANY ERRORS BUG 

            https://bst.cloudapps.cisco.com/bugsearch/bug/CSCua50697/?referring_site=bugquickviewredir

            Workaround 1: Reload the router with the T1 cable plugged in.

            Workaround 2:
            Step 1) Upgrade to a fixed-in Cisco IOS version.
            Step 2) Issue the following commands (hidden, so tab complete will not work):

            enable
            config t
            controller ! ( example: controller t1 0/0/0 )
            hwic_t1e1 equalize

            Step 3) Shut/no shut the T1 controller, or reload the router to allow the CLI to
            take effect.


            """
            T.insert(END, PRI_ISDN_shutdown)

        elif user_choice == "CME GUI":
            CME_GUI = """

            ENABLE CME GUI

            archive tar /xtract tftp://0.0.0.0/ggg.tar flash:  -  "(Copy and extract from TFTP (used for the GUI installation))"

            conf t

            ip http server  -  "(Enables http functionality on Cisco Router, uses port 80)"
            ip http authentication local  -  "(Enables local authentication)"
            no ip http secure-server  -  "(Disables https functionality)"
            ip http path flash:/abc  -  "(Look for HTML files in this [abc] directory)"
            
            "It doesn't matter whether you copy the HTML files into the flash root directory or in a folder, 
            but if you create a folder you can manage HTML files easily, that's the only advantage"

            file privilege 0 - default is 15  -  "(Specifies the file privilege level for the files. The level argument must be a number from 0 to 15. Users with privilege level equal to greater than the file privilege level can access the files under the file system.)"

            telephony-service
            web admin system name name1 password pass1  -  "(You can not set privilege level under Telephony-service for users)"
            dn-webedit  -  "(By default disabled (you can not add extensions). You will see notification message in your browser window: "add extension number through web is disabled")"
            time-webedit   -  "(By default disabled you can not change the time. You will see notification message in your browser window: "system time change time through web is not allowed")"

            http://192.168.1.199/ccme.html

            Conf t
            telephony-service
            service phone webAccess 0
            create cnf-files


            """
            T.insert(END, CME_GUI)

        elif user_choice == "CUE GUI":
            CUE_GUI = """

            CUE GUI 
            
            enable
            configure terminal
            ip http server
            ip http path flash:
            ip http authentication { aaa | enable | local | tacacs }
            exit 

            "Enabling GUI Access for the System Administrator"

            enable
            configure terminal
            telephony-service
            web admin system name username { password string | secret { 0 | 5 } string }
            dn-webedit
            time-webedit
            end


            """
            T.insert(END, CUE_GUI)

        elif user_choice == "DSPFARM Configuration with Gateway":
            DSPFARM_Conf = """

            EXAMPLE DPSFARM CONFIGURATION ON A VOICE GATEWAY 

            voice-card 0
            dsp services dspfarm
            exit
            
            sccp local gigabitEthernet 0/0
            sccp ccm <Router's address> identifier 1 version 7.0+
            sccp ccm group 1
            bind interface gigabitEthernet 0/0
            exit
            
            sccp
            dspfarm profile 1 transcode
            maximum sessions 10
            associate application sccp
            exit
            
            sccp ccm group 1
            associate ccm 1 priority 1
            associate profile 1 register ASDFGHJKL
            exit
            
            telephony-service
            sdspfarm units 1
            sdspfarm transcode sessions 10
            sdspfarm tag 1 ASDFGHJKL
            exit
            
            dspfarm profile 1 transcode
            no shut
            exit
            no sccp
            sccp
            
            
            "This is how to verify if the DSPFARM is successfully created and registered"
            
            
            show sccp
            SCCP Admin State: UP
            Gateway Local Interface: GigabitEthernet0/0
                    IPv4 Address: 10.122.148.27
                    Port Number: 2000
            IP Precedence: 5
            User Masked Codec list: None
            Call Manager: 10.122.148.27, Port Number: 2000
                            Priority: N/A, Version: 7.0, Identifier: 1
                            Trustpoint: N/A

            Transcoding Oper State: ACTIVE - Cause Code: NONE
            Active Call Manager: 10.122.148.27, Port Number: 2000
            TCP Link Status: CONNECTED, Profile Identifier: 1
            Reported Max Streams: 20, Reported Max OOS Streams: 0
            Supported Codec: g722r64, Maximum Packetization Period: 30
            Supported Codec: g711ulaw, Maximum Packetization Period: 30
            Supported Codec: g711alaw, Maximum Packetization Period: 30
            Supported Codec: g729ar8, Maximum Packetization Period: 60
            Supported Codec: rfc2833 dtmf, Maximum Packetization Period: 30
            Supported Codec: rfc2833 pass-thru, Maximum Packetization Period: 30
            Supported Codec: inband-dtmf to rfc2833 conversion, Maximum Packetization Period: 30


            """
            T.insert(END, DSPFARM_Conf)

        elif user_choice == "Conferencing (Ad Hoc / Meet Me)":
            Conferencing_AH = """

            EXAMPLE CONFIGURATION FOR CONFERENCING - AD HOC AND MEET ME 
            
            
            "Not everything included here is needed for the conferencing to work"


            voice-card 0
            dsp services dspfarm
            exit
            
            sccp local gigabitEthernet 0/0  -  "(Specifies the local SCCP Interface)"
            sccp ccm 192.168.10.1 identifier 100 version 7.0+  -  "(Configure the IP address of the call-agent to register the SCCP)"
            sccp

            sccp ccm group 1
            associate ccm 100 priority 1
            associate profile 1 register confprof1
            bind interface gigabitEthernet 0/0
            exit
            
            dspfarm profile 1 conference
             codec g711ulaw
             maximum conference-participants 8
             maximum sessions 8
             associate application sccp
             shutdown
             no shut
             
             
            telephony-service
            conference hardware
            max-ephones 10 
            max-dn 100
            ip source-address 192.168.10.1 port 2000
            sdspfarm units 1
            sdspfarm tag 1 confprof1
            transfer-system full-consult
            transfer-pattern .
            
            
            ephone-dn  5  octo-line
             number A000
             conference ad-hoc
             no huntstop
             
            ephone-dn  6  octo-line
             number A000
             conference ad-hoc


            MEET ME

            ephone-dn 7 octo-line
            description Meet-Me conference extension
            number 8000
            conference meetme
            no huntstop
            
            ephone-dn 78 octo-line
            description Meet-Me conference extension
            number 8000
            conference meetme
            
            
            ephone-template 1  -  "(Create a button template and assign it to the phones, so that the "Meet Me" soft key would be displayed)"
            softkeys connected Hold Endcall trnsfer Park Confrm ConfList Join Select RmLstC
            softkeys hold Resume Newcall Join Select 
            softkeys idle Redial newcall Cfwdall ConfList Join Login Pickup Gpickup Dnd
            softkeys seized Redial Endcall Cfwdall Pickup Gpickup Callback Meetme 
            
            ephone 1
            ephone-template 1  -  "(Assign the ephone-template under all phones which would use the "Meet Me" conferencing)"
            
            telephony-service
            create cnf-files
            restart all  -  "(Would restart all phones)"


            """
            T.insert(END, Conferencing_AH)

        elif user_choice == "DSPFARM with CUCM":
            IOS_Media_res = """

            CONFIGURE IOS BASED MEDIA RESOURCES TO BE REGISTERED WITH CUCM

            voice-card 0
            dsp service dspfarm 

            dspfarm profile 1 transcode 
            codec ...
            maximum sessions 2
            associate application sccp 
            no shut 

            dspfarm profile 2 conference
            codec g711ulaw
            maximum conference-participants 8
            maximum sessions 8
            associate application sccp
            shutdown
            no shut

            dspfarm profile 3 mtp
            codec ...
            codec pass-through 
            maximum sessions hardware sessions 1
            associate application sccp 
            no shut 

            sccp local gigabitethernet 0/0 
            sccp ccm 10.122.148.47 identifier 1 priority 1 version 7.0+  -  "(This is the CUCM's IP address)"

            sccp ccm group 1 
            bind interface gigabitethernet 0/0 
            associate ccm 1 priority 1 
            associate profile 1 register name trans_prof
            associate profile 2 register name conf_prof 
            associate profile 3 register name mtp_1 
            associate profile 3 register name mtp_2 

            sccp 


            """

            T.insert(END, IOS_Media_res)

        elif user_choice == "Phone Firmware Configuration":
            Phone_Firmware_Conf = """

            CONFIGURE FIRMWARE FOR PHONE 

            Upload the files to the flash (copy tftp: flash:)

            conf t

            tftp-server flash:FIRMWARE/apps45.9-4-2ES22.sbn alias apps45.9-4-2ES22.sbn
            tftp-server flash:FIRMWARE/cnu45.9-4-2ES22.sbn alias cnu45.9-4-2ES22.sbn
            tftp-server flash:FIRMWARE/cvm45sccp.9-4-2ES22.sbn alias cvm45sccp.9-4-2ES22.sbn
            tftp-server flash:FIRMWARE/dsp45.9-4-2ES22.sbn alias dsp45.9-4-2ES22.sbn
            tftp-server flash:FIRMWARE/jar45sccp.9-4-2ES22.sbn alias jar45sccp.9-4-2ES22.sbn
            tftp-server flash:FIRMWARE/SCCP45.9-4-2SR2-2S.loads alias SCCP45.9-4-2SR2-2S.loads
            tftp-server flash:FIRMWARE/term45.default.loads alias term45.default.loads
            tftp-server flash:FIRMWARE/term65.default.loads alias term65.default.loads

            telephony-service
            load 7965 SCCP45.9-4-2SR2-2S
            create cnf-files
            ephone 2 
            restart 

            <FOR SIP PHONES>

            voice register global
            load 7965 SCCP45.9-4-2SR2-2S
            create profile

            voice register pool
            restart


            """

            T.insert(END, Phone_Firmware_Conf)

        elif user_choice == "Paging Configuration (SCCP)":
            Paging_Config = """

            CONFIG PAGING 

            ephone-dn 10
            number 1212
            name PAGING
            paging ip 239.1.1.10 port 2000  -  "(Multicast address)"
            ephone 1
            paging-dn 10 multicast
            ephone 2
            paging-dn 10 multicast


            """

            T.insert(END, Paging_Config)

        elif user_choice == "Speed Dial SCCP Phones":
            Speed_Dial_SCCP = """

            CONFIGURE SPEED DIAL CME SCCP 

            ephone 2
            speed-dial 1 270000 label "Speed-Dial"

            telephony-service
            create cnf-files

            ephone 2
            restart


            """

            T.insert(END, Speed_Dial_SCCP)

        elif user_choice == "CME Night Service":
            night_service = """

            CME - NIGHT SERVICE

             Configuration Template

            telephony-service
             night-service day day start-time stop-time
             night-service date month date start-time stop-time
             night-service everyday start-time stop-time
             night-service weekday start-time stop-time
             night-service weekend start-time stop-time
             night-service code digit-string
             timeouts night-service-bell seconds
            !
            ephone-dn dn-tag
             night-service bell
            !
            ephone phone-tag
             night-service bell

            1. Define Night-Service time slots

            telephony-service
             night-service day Sun 08:00 07:59
             night-service day Mon 17:00 07:59
             night-service day Tue 17:00 07:59
             night-service day Wed 17:00 07:59
             night-service day Thu 17:00 07:59
             night-service day Fri 17:00 07:59
             night-service day Sat 08:00 07:59

            2. Configure call-forward night-service command under the ephone-dn.

            ephone-dn 19
             number 8500
             label Front Desk
             name Front Desk
             call-forward busy 9201
             call-foward noan 9202 timeout 10
             call-forward night-service 8501
             night-service bell

            - Assuming 8500 is the Front Desk number. As per the above configuration of ephone-dn during non night-service hours the call was forward to the 9201 and 9202 when busy or no answer. 
            - During night-service hours the call would be redirected to 8501 which could your Auto-Attendant number or it could be another destination. It could be pointing to a dial-peer which further points to your cell/home number. For example :- 

            dial-peer voice 20 pots
             description == Security Room ==
             destination-pattern 8501
             port 1/1

            - With the above configuration, the call will be sent to this dial-peer which is an Analog Phone in the security room. 


            """

            T.insert(END, night_service)

        elif user_choice == "B-ACD":

            B_ACD = """

            B-ACD Basic Example Configuration


            voice hunt-group 1 parallel
             list 1012,1010,1014,1011
             timeout 30
             pilot 1111
            !
            !
            voice hunt-group 2 sequential
             list 1012,1010,1014,1011
             timeout 10
             pilot 7000


            application
            service queue flash:app-b-acd-3.0.0.4.tcl
            param number-of-hunt-grps 2
            param aa-hunt2 7000
            param aa-hunt3 1111
            param queue-len 15
            param queue-manager-debugs 1

            service aa flash:app-b-acd-aa-3.0.0.4.tcl
            paramspace english index 1
            paramspace english language en
            paramspace english location flash:
            param service-name queue
            param handoff-string aa
            param aa-pilot 8005550100
            param welcome-prompt _bacd_welcome.au
            param number-of-hunt-grps 2
            param dial-by-extension-option 1
            param second-greeting-time 60
            param call-retry-timer 15
            param max-time-call-retry 700
            param max-time-vm-retry 2
            param voice-mail 5003

            !

            dial-peer voice 1000 pots
             service aa
             incoming called-number 8005550100
             port 0/0/0:23
            !
            dial-peer voice 1004 voip
             service aa
             destination-pattern 8005550100
             session target ipv4:192.168.130.12
             incoming called-number 8005550100
             dtmf-relay h245-alphanumeric
             codec g711ulaw
             no vad

             === CME11.6 files ===
            app-b-acd-3.0.0.4.tcl
            app-b-acd-aa-3.0.0.4.tcl
            en_bacd_allagentsbusy.au
            en_bacd_disconnect.au
            en_bacd_enter_dest.au
            en_bacd_invalidoption.au
            en_bacd_music_on_hold.au
            en_bacd_options_menu.au
            en_bacd_welcome.au

            NeverGonnaGiveYouUp_pcm_ulaw-1495111440.wav  ===> "(MOH under Telephony Service)"

            dial-peer voice 110 voip
             service aa
             destination-pattern 10000
             session target ipv4:10.122.148.26
             incoming called-number 10000
             dtmf-relay rtp-nte
             codec g711ulaw
             no vad 

            CSCuh94827,CSCti34003, bugs releated


            """

            T.insert(END, B_ACD)

        elif user_choice == "Hunt Group (Normal)":
            Hunt_group_normal = """

            CALL HUNT GROUP - normal 

            ephone-hunt 1 peer 
            pilot 4446
            list 1001, 1002, 1003,
            final 4004
            timeout 30 
            hops 30
            auto logout 2


            """

            T.insert(END, Hunt_group_normal)

        elif user_choice == "Hunt Group (Simultaneous)":
            Hunt_group_simult = """

            CALL HUNT GROUP 
            
            "Call all phones simultaneously"

            voice hunt-group 4 parallel
            pilot 1000
            list 1001, 1002, 1003, 1004
            final 2000
            timeout 20 


            """

            T.insert(END, Hunt_group_simult)

        elif user_choice == "Call Forwarding":
            Call_Forward = """

            CALL FORWARDING 

            Router(config)#ephone-dn 2
            Router(config-ephone-dn)#call-forward noan 3333 timeout 15


            """

            T.insert(END, Call_Forward)

        elif user_choice == "Call Parking":
            Call_Park = """

            CALL PARK 

            ephone-dn 4
            number 0000
            park-slot timeout 10 limit 2 recall
            
            telephony service 
            call-park system application 
            create cnf-files


            """

            T.insert(END, Call_Park)

        elif user_choice == "Transfer call from CME to CUCM":
            Transfer_CME_CUCM = """

            ENABLE TRANSFER IN CME TO CUCM 

            telephony-service
            transfer-system full-consult
            transfer-pattern 27....
            create cnf-files


            """

            T.insert(END, Transfer_CME_CUCM)

        elif user_choice == "CUE Installation":
            CUE_Install = """

            INSTALL CUE (SRE) 

            int sm1/0
            ip unnumbered
            no shut 
            service-module ip address 10.122.148.8 255.255.255.192
            service-module ip default-gateway 10.122.148.27
            exit
            ip route 10.122.148.8 255.255.255.192 sm1/0

            service-module sm1/0 install url ftp://username:password@172.18.110.87/cue-vm-k9.SPA.sme.8.6.10.pkg                                         Delete the installed Cisco Unified SIP Proxy and proceed with new installation? [no]: y
            service-module sm1/0 session 


            """

            T.insert(END, CUE_Install)

        elif user_choice == "CUE Configuration":
            CUE_Config = """

            CONFIGURE CUE ON CME 
            
            
            "This configuration is for voicemail (mailbox) and auto-attendant"

            "License Activation on CUE:"

            show license evaluation
            license activate voicemail mailboxes 500
            license activate ports 32
            wr
            reload  -  "(reloads the module)"

            "On the CME"

            conf t 
            ephone-dn 
            call-forward noan 6800 timeout 15


            "Configure the voicemail  (On CUE)"

            conf t
            ccn application voicemail 
            description "Voice Mail"
            maxsessions 8  
            
            conf t 
            username user1 create
            username user1 fullname display "Vlkolev 1"
            username user1 phonenumber 272222
            voicemail mailbox owner user1
            enable
            expiration time 10
            greeting standard recording-type system-default
            mailboxsize 300
            messagesize 120
            tutorial
            end
            
            ccn trigger sip phonenumber 6000
            application "voicemail"
            enabled
            maxsessions 1
            end trigger

            "Configure the AutoAttendant:"

            ccn application AutoAttendant
            maxsessions 4
            parameter "operExtn" "1000"
            parameter "MaxRetry" "3"
            parameter "welcomePrompt" "ciscowelcome.wav"
                     
            ccn trigger sip phonenumber 6001
            application autoattendant
            enabled
            maxsessions 2
            end trigger

            "Configure AvT:"


            ccn trigger sip phonenumber 6002
            application promptmgmt
            enabled
            maxsessions 1
            end  trigger


            Configuration on CME:

            dial-peer voice 12 voip
            destination-pattern 6...
            session protocol sipv2
            session target ipv4:10.122.148.8
            dtmf-relay sip-notify
            codec g711ulaw
            no vad

            ephone-dn 1
            all-forward noan 6000 timeout 8

            allow-connections h323 to sip
            allow-connections sip to h323
            allow-connections sip to h323


            Configure CCN-subsystem

            ccn subsystem sip
             gateway address "172.18.106.105"
             end subsystem


            """

            T.insert(END, CUE_Config)

        elif user_choice == "MWI CUE":
            MWI_CUE = """

            CONFIGURE MWI OUTCALL ON CUE 

            On CUE: 

            ccn subsystem sip
            mwi sip outcall
            exit
            show ccn subsystem sip
            conf t
            ccn application ciscomwiapplication
            parameter strMWI_ON_DN 8000
            parameter strMWI_OFF_DN 8001
            exit


            On CME:

            ephone-dn 6
            number 8000......
            mwi on
            
            ephone-dn 7
            number 8001......
            mwi off

            telephony-service
            voicemail 6000 (voicemail number)  -  "(This is to use the envelope icon on the phone.)"
            create cnf-files 


            """

            T.insert(END, MWI_CUE)

        elif user_choice == "SRST SCCP Configuration":
            SRST_Config = """

            CONFIG SCCP SRST ON ROUTER 

            call-manager-fallback 
            ip source-address <ip address> <port (2000)>
            max-ephones 
            max-dn (dual-line, octo-line)

            call-manager-fallback
            shut
            no shut


            """

            T.insert(END, SRST_Config)

        elif user_choice == "CME SRST":
            CME_SRST = """

            CONFIG SCCP CME SRST CME ON ROUTER 

            telephony-service
            srst mode auto-provision all
            srst dn line-mode dual
            srst dn template 1
            srst ephone template 1
            srst ephone description SRST FOR CUCM
            ip source-address 10.122.148.27
            max-dn 20
            max-ephones 10


            """

            T.insert(END, CME_SRST)

        elif user_choice == "MGCP SRST":
            MGCP_SRST = """

            CONFIG MGCP FALLBACK SRST 

            ccm-manager fallback-mgcp 
            ccm-manager mgcp 
            ccm-manager config server 10.122.148.47

            application
            global
            service alternate default 

            dial-peer voice 1 pots 
            destination-pattern 9T 
            incoming called-number .
            direct-inward-dial 
            port 0/0/0:15 

            dial-peer voice 2 pots 
            application mgcpapp 
            incoming called-number .
            direct-inward-dial
            port 0/0/0:15 

            call-manager-fallback 
            ip source-address 10.122.148.27 port 2000
            max-dn 20
            max-ephone 10 
            shut
            no shut


            """

            T.insert(END, MGCP_SRST)

        elif user_choice == "SIP SRST":
            SIP_SRST = """

            CONFIG SIP SRST 

            voice service voip
            allow-connections sip to sip
            allow-connections h323 to sip
            allow-connections sip to h323
            sip
            registrar server
            
            voice register global
            default mode
            system message SIP SRST
            max-dn 25
            max-pool 15
            
            voice register pool 1
            id network 10.63.123.0 mask 255.255.255.0
            codec g711ulaw
            dtmf-relay rtp-nte sip-notify

            """

            T.insert(END, SIP_SRST)

        elif user_choice == "COR List Configuration":
            COR_list_config = """

            COR LIST CONFIG 

           "With this configuration:

               - dn 1001 can call all numbers
               - dn 1002 can call all number except "call1900"
               - dn 1003 can call only emergency and local calls
               - dn 1004 can call all numbers (has no corlist applied)" 


            dial-peer cor custom
              name emergency
              name local_call
              name call1800
              name call1900
            !
            dial-peer cor list Manager
              member emergency
              member local_call
              member call1800
              member call1900
            !
            dial-peer cor list Facilities
              member emergency
              member local_call
              member call1800
            !
            dial-peer cor list Guest
              member emergency
              member local_call
            !
            dial-peer voice 1 voip
              destination-pattern 408….
              session target ipv4:1.1.1.1
              corlist outgoing calllocal
            !
            dial-peer voice 2 voip
              destination-pattern 1800…
              session target ipv4:1.1.1.1
              corlist outgoing call1800
            !
            dial-peer voice 3 pots
              destination-pattern 1900…
              port 1/0/0
              corlist outgoing call1900
            !
            dial-peer voice 4 pots
              destination-pattern 911
              port 1/0/1
              corlist outgoing emergency
            !
            dial-peer voice 5 pots
              destination-pattern 316….
              port 1/1/0
            !
            ephone-dn 1
              number 1001
              cor incoming Manager
            !
            ephone-dn 2
              number 1002
              cor incoming Facilities
            !
            ephone-dn 3
              number 1003
              cor incoming Guest
            !
            ephone-dn 4
              number 1004 


             """

            T.insert(END, COR_list_config)

        elif user_choice == "Call Blocking":
            Call_Block = """ 

            SPECIFIC CALL BLOCK CONFIG


            "Configure the following to block calls from 1234567"

            Voice translation-rule 100
            rule 1 reject /1234567/
            
            Voice translation-profile BLOCK
            translate calling 100
            
            dialpeer voice 1 pots
            incoming called-number .
            call-block translation-profile incoming BLOCK
            call-block disconnect-cause incoming call-reject


            """

            T.insert(END, Call_Block)

        elif user_choice == "Toll Fraud Configuration":
            Toll_fraud_config = """

            TOLL-FRAUD CONFIGURATION 
            

            voice service voip                                    
                ip address trusted authenticate
                ipv4 ..... <IP/Network address that you'd like to permit for voice>

            
            
            "All IP addresses that are configured in the VOIP dial-peers would be automatically trusted"


            """

            T.insert(END, Toll_fraud_config)

        elif user_choice == "Clear a call":
            Clear_call = """

            HOW TO CLEAR A STUCK CALL

            show call active voice  - get the ID (112B) for the call leg(s)
            clear call voice causecode 1 id 112B


            """

            T.insert(END, Clear_call)

        elif user_choice == "Music On Hold":
            Music_on_hold = """

            CONFIGURE MOH AND MULTICAST MOH


            conf t
            telephony-service
            moh filename  -  "(For unicast MOH)"
            multicast moh ip-address port port-number  -  "(For multicast MOH)"
            ccm-manager music-on-hold  -  "(FOR CUCM)"
            exit
            
            ephone phone-tag
            multicast-moh  -  "(For multicast MOH)"
            end 

            
            "Multicast MOH wouldn't work over WAN"


            ENABLE MULTICAST ON INTERFACE (for multicast MOH)


            conf t
            interface gigabitethernet 0/0
            ip pim sparse-mode

            conf t 
            ip multicast-routing


            """

            T.insert(END, Music_on_hold)

        elif user_choice == "Verify IOS Image (MD5)":
            Verify_image = """

            VERIFY IOS IMAGE

            verify flash:nameoffile   - verify if image is ok (check md5 with the md5 in www.cisco.com)


            """

            T.insert(END, Verify_image)

        elif user_choice == "Fast Track Configuration":
            Fast_track_config = """

            FAST-TRACK EXAMPLE CONFIGURATION


            voice register pool-type  7841
             xml-config maxNumCalls 4
             xml-config busyTrigger 2
             telnet-support
             gsm-support
             transport tcp
             num-lines 4
             addons 2
             description Cisco IP Phone 7841
             reference-pooltype 6941
            !
            voice register pool  1
             busy-trigger-per-button 1
             id mac 0008.2F1B.747B
             type 7841
             number 1 dn 1
             template 1
             dtmf-relay rtp-nte
             description MY PHONE


             """

            T.insert(END, Fast_track_config)

        elif user_choice == "CPU Spike Script":
            CPU_SPIKE_SCRIPT = """

            CPU SPIKE SCRIPT 

            event manager applet capture_cpu_spike
            event snmp oid 1.3.6.1.4.1.9.2.1.56 get-type next entry-op ge entry-val 70 exit-time 10 poll-interval 1
            action 1.0 syslog msg "CPU Utilization is high"
            action 2.0 cli command "en"
            action 2.5 cli command "show proc cpu sort | append flash:cpuinfo"
            action 3.0 cli command "show proc cpu sort | append flash:cpuinfo"
            action 4.0 cli command "show call active voice brief | append flash:cpuinfo"
            action 5.0 cli command "show voip rtp connection | append flash:cpuinfo"
            action 6.0 cli command "show log | append flash:cpuinfo"
            action 7.0 cli command "show mem stat his | append flash:cpuinfo"
            action 8.0 cli command "show proc cpu his | append flash:cpuinfo"
            action 9.0 cli command "show align | append flash:cpuinfo"


            """

            T.insert(END, CPU_SPIKE_SCRIPT)

        elif user_choice == "Test translation rule":
            test_translate = """

            TEST TRANSLATION RULE 

            test voice translation-rule 110 16172756959 


            """

            T.insert(END, test_translate)

        elif user_choice == "4K Packet Capture":
            Router_4K_PCap = """

            PACKET Capture 4400 routers

            monitor capture TAC interface ... both 
            monitor capture TAC match ipv4 any any 
            monitor capture TAC start 
            monitor capture TAC stop
            monitor capture TAC clear
            monitor capture TAC export flash:/filename.pcap 


            """

            T.insert(END, Router_4K_PCap)

        elif user_choice == "4K ISDN PRI configuraiton":
            ISR_4K_ISDN = """

            ISR 4K PRI CLOCKING CONFIGURATION

            network-clock synchronization participate <slot/subslot>  -  "(Need to remove this from the CLI (if we don't want to synch to the Backplane))"
            network-clock input-source <priority> controller <t1/e1> <slow/subslot/port>  -  "(Most of the times we need to remove this from the CLI (if there) - could be used when the customer has two different providers)" 

            network-clock synchronization automatic -  "(This is REQUIRED)"

            controller t1 0/0/0
            clock source line primary/secondary  -  "(This is REQUIRED)"


            """

            T.insert(END, ISR_4K_ISDN)

        elif user_choice == "4K DSP Farm":
            DSPFARM_4K = """

            DSPFARM on 4k - uses the motherboard PVDM

            voice-card 0/4
            dsp services dspfarm 

            the rest is like the usual DSP Farm configuration


            """

            T.insert(END, DSPFARM_4K)

        elif user_choice == "CUE with CUCM":
            CUE_CUCM = """

            CUE REGISTERED WITH CUCM (Only the CUE part of the configuration)


            VNT-AIM-CUE1#show run
            Generating configuration:


            clock timezone America/New_York

            hostname VNT-AIM-CUE1

            ip domain-name cisco.com

            ntp server 172.18.106.15

            groupname Administrators create

            username administrator create
            username marschne create
            username jdoe create
            username marschne phonenumber "2104"
            username jdoe phonenumber "2103"

            groupname Administrators member administrator
            groupname Administrators member marschne
            groupname Administrators privilege superuser
            groupname Administrators privilege ManagePrompts

            backup server url "ftp://127.0.0.1/ftp" credentials hidden 
            "EWlTygcMhYmjazXhE/VNXHCkplVV4KjescbDaLa4fl4WLSPFvv1rWUnfGWTYHfmPSd8ZZNgd+
            Y9J3xlk2B35jwAAAAA="

            ccn application autoattendant
             description "autoattendant"
             enabled
             maxsessions 4
             script "aa.aef"
             parameter "MaxRetry" "3"
             parameter "operExtn" "0"
             parameter "welcomePrompt" "AAWelcome.wav"
             end application

            ccn application ciscomwiapplication
             description "ciscomwiapplication"
             enabled
             maxsessions 4
             script "setmwi.aef"
             parameter "strMWI_OFF_DN" "8001"
             parameter "strMWI_ON_DN" "8000"
             parameter "CallControlGroupID" "0"
             end application

            ccn application promptmgmt
             description "promptmgmt"
             enabled
             maxsessions 1
             script "promptmgmt.aef"
             end application

            ccn application voicemail
             description "voicemail"
             enabled
             maxsessions 4
             script "voicebrowser.aef"
             parameter "logoutUri" "http://localhost/voicemail/vxmlscripts/mbxLogout.jsp"
             parameter "uri" "http://localhost/voicemail/vxmlscripts/login.vxml"
             end application

            ccn engine
             end engine

            ccn subsystem jtapi
             ctiport 28001 28002 28003 28004 
             ccm-manager address 14.80.227.127 14.80.227.128
             ccm-manager credentials hidden "+DuGhIBvqsghj6p6aBUoRQ4E0vzCD5YHSd8ZZNgd+
             Y9J3xlk2B35j0nfGWTYHfmPSd8ZZNgd+Y9J3xlk2B35jwAAAAA="
             end subsystem

            ccn subsystem sip
             gateway address "172.18.106.105"
             end subsystem

            ccn trigger jtapi phonenumber 28000
             application "voicemail"
             enabled
             locale "en_US"
             maxsessions 4
             end trigger

            ccn trigger jtapi phonenumber 28100
             application "autoattendant"
             enabled
             locale "en_US"
             maxsessions 4
             end trigger

            ccn trigger jtapi phonenumber 28111
             application "promptmgmt"
             enabled
             locale "en_US"
             maxsessions 1
             end trigger

            ccn trigger sip phonenumber 28000
             application "voicemail"
             enabled
             locale "en_US"
             maxsessions 4
             end trigger

            ccn trigger sip phonenumber 28100
             application "autoattendant"
             enabled
             locale "en_US"
             maxsessions 4
             end trigger

            ccn trigger sip phonenumber 28111
             application "promptmgmt"
             enabled
             locale "en_US"
             maxsessions 1
             end trigger

            voicemail default expiration time 30
            voicemail default language en_US
            voicemail default mailboxsize 420
            voicemail recording time 900
            voicemail default messagesize 60
            voicemail operator telephone 0
            voicemail capacity time 480
            voicemail mailbox owner "jdoe" size 420
             description "jdoe mailbox"
             end mailbox

            voicemail mailbox owner "marschne" size 420
             description "marschne mailbox"
             end mailbox

            end


            """

            T.insert(END, CUE_CUCM)

        elif user_choice == "License Accept 4K":
            license_acc_4k = """

            ACCEPT UCK9 LICENSE ON 4K ROUTERS

            license accept end user agreement 
            license boot level uck9


            """

            T.insert(END, license_acc_4k)

        elif user_choice == "CUE to Email Notification":

            CUE_email = """

            CUE to EMAIL notification

            1)Go to voicemail->Message Notification->Notification Administration

            -Make sure "Enable system-wide notification for" is checked, and set for
            "All Messages"

            -Check "Allow user to login to voicemail box to retrieve voicemail when
            phone notification device is notified."

            -Check "Attach voice messages to email notification messages." Click Apply

            2)Go to System -> Domain name settings -> set your domain name
            (mycompany.com) (this is a big one, this needs to be set)

            3)Go to System -> Domain name settings -> set your DNS server if you
            have one. Click Apply

            4)Go to System -> SMTP Settings -> Set your SMTP server address, as well
            as any authentication if needed. Click Apply

            5) Go to Configure -> User -> choose user -> check the "Enable notification for
            this user" box at bottom of the screen. Click Apply

            6) Go to Configure -> User -> notification tab -> click on "email inbox"

            -Input the users email address
            -Input a subject text for the email
            -Check box "Enable notification to this device "
            -Check box "Attach voice message to email notification messages."
            -Change "Notification Preference" to "All Messages"
            -Set up the Notification schedule, these are the hours that e-mails will be
            sent. Click Apply

            7) On the UC520 router, set your "domain-name" and "ip name-server".

            Ping the smtp server from the CUE.



            summary of the steps to do this from the CLI, maybe could be usefull.

            To log into CUE from CME:
            #session Service-Engine1/0 session

            Configuring an SMTP Server
            1. config t
            2. smtp server address {hostname | ip-address}
            3. end

            Configuring System-Wide Settings
            1. config t
            2. voicemail notification enable
            3. voicemail notification preference {all | urgent}
            4. voicemail notification email attach
            5. voicemail configuration outgoing-email from-address <email-address>
            6. end

            Enabling Message Notification for a Subscriber
            1. config t
            2. voicemail notification owner owner-id enable

            Configuring Message Notification for E-mail
            1. enable mode
            2. username username profile vm-notif-profile email address email-address
            3. username username profile vm-notif-profile email enable
            4. username username profile vm-notif-profile email attach
            5. username username profile vm-notif-profile email preference {all |
            urgent}
            6. username username profile vm-notif-profile email schedule day
            <day-of-week> active from <hh:mm> to <hh:mm>
            7. username username profile vm-notif-profile email text <email-text>

            To check configuration:
            1. show smtp server
            2. show voicemail configuration
            3. show voicemail notification
            4. show voicemail notification restriction-table
            5. show voicemail notification owner owner-id profile
            6. show voicemail notification owner owner-id email 


            """

            T.insert(END, CUE_email)

        elif user_choice == "VRF with SIP/H323":
            vrf_SIP_or_H323 = """

            VRF with SIP or H323

            voice vrf <vrf name>


            """

            T.insert(END, vrf_SIP_or_H323)

        elif user_choice == "How to collect debugs the right way":
            collect_debug_properly = """

            BEFORE DEBUGGING 

            service sequence-numbers
            service timestamps debug datetime localtime msec
            logging buffered 10000000 debugging
            no logging console
            no logging monitor 
            clear log 


            SENDINDG DEBUGS TO A SYSLOG SERVER
            
            service sequence-numbers
            service timestamps debug datetime localtime msec
            logging host <syslog server> transport <type> port <port>
            logging trap debug 


            """

            T.insert(END, collect_debug_properly)

        elif user_choice == "Upgrade DSP Firmware":
            collect_debug_properly = """

            BEFORE DEBUGGING 

            service sequence-numbers
            service timestamps debug datetime localtime msec
            logging buffered 10000000 debugging
            no logging console
            no logging monitor 
            clear log 


            SENDINDG DEBUGS TO SERVER
            +
            logging host <syslog server> transport <type> port <port>
            logging trap debug 


            """

            T.insert(END, collect_debug_properly)

        elif user_choice == "Reset DSP":
            dsp_reset = """

            TEST COMMANDS (This doesn't work on 4K routers)

            test voice driver  -  "(Hidden command for older IOS and DSP)"
            test dsp device all all reset  -  "(For newer IOS)"


            """
            T.insert(END, dsp_reset)

        elif user_choice == "Modem Passthrough with SIP, SCCP and MGCP Gateways":
            modem_pass = """

            MODEM PASSTHROUGH WITH SIP AND SCCP/MGCP GAETWAYS

            Call flows:
            VG224 --- SCCP --- CUCM --- SIP --- 3900 --- PRI --- PSTN
            VG224 --- MGCP --- CUCM --- H323 --- 3900 --- PRI --- PSTN

            In the above call flows, fax or modem switchover will not happen if you have the following configuration:

            dial-peer voice 1 voip
             modem passthrough nse codec g711ulaw

            This is due to NSE capability mismatch in the SIP SDP, since CUCM is not aware of NSE. 

            The solution / workaround is to use the following configuration:

            dial-peer voice 1 voip
             modem relay nse codec g711ulaw gw-controlled 

            For further details refer to: http://cdetsweb-prd.cisco.com/apps/dumpcr?identifier=CSCsr89830 


            """
            T.insert(END, modem_pass)

        elif user_choice == "MWI with QSIG":
            mwi_qsig = """
            
            MWI OVER QSIG PRI 

                1. Disable the QSIG configuration under the SIP trunk in the CUCM
                2. Configure MWI server with the CUCM's IP address (Not Unity) under "sip-ua"
                3. Configure the following in the gateway:

                voice service voip
                qsig decode


                    """
            T.insert(END, mwi_qsig)

        elif user_choice == "EEM Script - Automatic Packet Capture When IP SLA goes down":
            eem_script_capture = """
            
            "This configuraiton will run an automatic capture when IP SLA to certain device goes down. 
            The packet capture will run for 5 minutes and will be saved on the flash: after that.
            Please keep in mind that an EEM script needs minimum of 2 TTY lines available in order to work:"
            
                ip sla 1
                icmp echo <Device IP address> source-interface gigabitethernet 0/1
                exit
                track 1 ip sla 1 reachability
                exit
                ip sla schedule 1 life forever start-time now
                
                track 100 list boolean or
                object 1
                
                event manager applet CAPTURE_1
                 event track 100 state down maxrun 350
                 action 01 cli command "enable"
                 action 02 cli command "conf t"
                 action 03 cli command "ip access-list extended CAP-FILTER"
                 action 04 cli command "permit ip any any"
                 action 05 cli command "end"
                 action 06 cli command "monitor capture buffer CAP-BUF size 102400 max-size 1514"
                 action 07 cli command "monitor capture buffer CAP-BUF filter access-list CAP-FILTER"
                 action 08 cli command "monitor capture point ip process-switched CAP-POINT both"
                 action 09 cli command "monitor capture point associate CAP-POINT CAP-BUF"
                 action 10 cli command "monitor capture point start CAP-POINT"
                 action 11 wait 320
                 action 12 cli command "monitor capture point stop CAP-POINT"
                 action 13 cli command "monitor capture buffer CAP-BUF export flash:BUF.pcap" pattern "BUF.pcap"
                 action 14 cli command "" pattern "confirm"
                 
                 
            "You can also use the script to detect particular events in the logs and trigger an action. For example:"
            
                event manager applet capture
                action 1.0 syslog msg "Paste the log message here"
                action 2.0 cli command "en"
                action 3.0 cli command "show call active voice br | append flash:cpuinfo"
                 
                 
            "Troubleshooting the EEM script:"
            
            debug event manager action cli
            
            
                    """
            T.insert(END, eem_script_capture)

        elif user_choice == "Voiceview express":
            voiceview_express = """
            
            VOICEVIEW EXPRESS EXAMPLE CONFIGURATION
            
            url authentication http://192.168.130.19/voiceview/authentication/authenticate.do
            url services http://192.168.130.19/voiceview/common/login.do
            
            CUE configuration:
            1. conf t
            2. service voiceview
            3. enable
            4. session idletimeout 10
            5. end
            6. end
            7. (Optional) show voiceview configuration
            8. (Optional) show voiceview sessions
            ====================================
            1. conf t
            2. site name local
            3. phone-authentication username admin password cisco
            4. end
            5. show phone-authentication configuration
            ====================================
            conf t
            service phone-authentication
            fallback-url http://192.168.130.18/CCMCIP/authenticate.asp
            
            "Add the credentials for CME and CME IP in CUE GUI - the same configured under "telephony-service" (web admin system name admin password cisco)"
            
            ++++++++++++++++++++++++++++++++++++++++++++
            
            CME Configuration:
            
            CME GUI should be enabled
            
            conf t
            telephony-service
            authentication credential admin cisco
            service phone webAccess 0
            url services http://192.168.130.19/voiceview/common/login.do
            url authentication http://192.168.130.19/voiceview/authentication/authenticate.do
            voicemail 6000
            web admin system name admin password cisco

            This configuraiton will run an automatic capture when IP SLA to certain device goes down. 
            The packet capture will run for 5 minutes and will be saved on the flash: after that.
            Please keep in mind that an EEM script needs minimum of 2 TTY lines available in order to work:

                ip sla 1
                icmp echo <Device IP address> source-interface gigabitethernet 0/1
                exit
                track 1 ip sla 1 reachability
                exit
                ip sla schedule 1 life forever start-time now

                track 100 list boolean or
                object 1

                event manager applet CAPTURE_1
                 event track 100 state down maxrun 350
                 action 01 cli command "enable"
                 action 02 cli command "conf t"
                 action 03 cli command "ip access-list extended CAP-FILTER"
                 action 04 cli command "permit ip any any"
                 action 05 cli command "end"
                 action 06 cli command "monitor capture buffer CAP-BUF size 102400 max-size 1514"
                 action 07 cli command "monitor capture buffer CAP-BUF filter access-list CAP-FILTER"
                 action 08 cli command "monitor capture point ip process-switched CAP-POINT both"
                 action 09 cli command "monitor capture point associate CAP-POINT CAP-BUF"
                 action 10 cli command "monitor capture point start CAP-POINT"
                 action 11 wait 320
                 action 12 cli command "monitor capture point stop CAP-POINT"
                 action 13 cli command "monitor capture buffer CAP-BUF export flash:BUF.pcap" pattern "BUF.pcap"
                 action 14 cli command "" pattern "confirm"


            Troubleshooting the EEM script:

            debug event manager action cli
            
            
                    """
            T.insert(END, voiceview_express)

            # T.delete('1.0', END)

        elif user_choice == "Fax Configuration":
            fax_config = """

            MODEM PASSTHROUGH NSE
            
                SIP/H323
                
                voice service voip
                modem passthrough nse codec g711ulaw
                
                            or
                
                dial-peer voice 1 voip
                modem passthrough nse codec g711ulaw
                
                
                SCCP 
                
                voice service voip
                modem passthrough nse codec g711ulaw
                
                
                MGCP
                
                mgcp modem passthrough voip mode nse
                mgcp modem passthrough voip codec g711ulaw
                
            
            FAX PASS-THROUGH (Protocol Based)
            
                SIP/H323
                
                voice service voip
                fax protocol pass-through g711ulaw
                
                            or
                
                dial-peer voice 1 voip
                fax protocol pass-through g711ulaw
                
                
                MGCP
                
                Fax pass-through is NOT supported for MGCP
                
                
                SCCP
                
                Fax pass-through is NOT supported for MGCP
                
                
            T38 NSE-BASED
            
                SIP/H323
                
                voice service voip
                fax protocol t38 nse ls-redundancy 0 hs-redundancy 0 fallback pass-through
                
                                                    or
                                                    
                dial-peer voice 1 voip
                fax protocol t38 nse ls-redundancy 0 hs-redundancy 0 fallback pass-through
                
                
                MGCP 
                
                no mgcp fax t38 inhibit (enabled by default)
                
                
                SCCP
                
                voice service voip
                fax protocol t38 nse ls-redundancy 0 hs-redundancy 0 fallback pass-through
                
                
            T38 PROTOCOL-BASED       
                
                SIP/H323
            
                
                voice service voip
                fax protocol t38 version [0|3] ls-redundancy 0 hs-redundancy 0 fallback pass-through
                
                                                    or
                                                    
                dial-peer voice 1 voip
                fax protocol t38 version [0|3] ls-redundancy 0 hs-redundancy 0 fallback pass-through
                
                
                MGCP
                
                
                mgcp package-capability fxr-package
                mgcp default-package fxr-package
                
                
                SCCP
                
                
                SCCP does not support protocol-based T38
                

                    """
            T.insert(END, fax_config)


        elif user_choice == "Span port configuration on a switch":
            span_port = """

            SPAN PORT CONFIGURATION ON THE SWITCH (FOR COLLECTING PACKET CAPTURE FROM A PHONE)            
             
            conf t
            monitor session 1 source interface g1/0/32 both            
            monitor session 1 destination interface g5/0/41
                                     
            Disable with             
                         
            no monitor session 1 destination interface g5/0/41


                    """
            T.insert(END, span_port)


        elif user_choice == "LPCOR Configuration":
            lpcor_config = """

            LPCOR CONFIGURATION

            
            sh run | sec aaa            
            aaa new-model           
            aaa authentication login h323 local            
            aaa authorization exec h323 local            
            aaa authorization network h323 local            
            aaa accounting connection h323            
            aaa session-id common            
            gw-accounting aaa
                                                 
                                                                                     
            username 1111 password 0 1111
            username 2222 password 0 2222
                         
                         
            voice lpcor enable            
            voice lpcor custom            
            group 10 PRI            
            voice lpcor policy PRI            
            service fac            
            accept PRI fac                        
             
            *** We need this config under "application" and  "package auth". Check if the files "enter_pin.au" and "enter_account.au" are on the flash ***
            
            application           
            package auth            
              param max-digit 5            
              param max-retries 3            
              param passwd-prompt flash:enter_pin.au            
              param user-prompt flash:enter_account.au            
              param abort-digit *            
              param term-digit #            
             
            
            *** Check for trunk config with lpcor assigned ***
                       
            trunk group PRI           
            lpcor outgoing PRI
            
            
            *** Make shure we have configured  "trunk-group PRI" under Serial interface and "trunkgroup PRI" under the dial-peer.***
                        
            interface Serial0/0/0:23            
            no ip address            
            encapsulation hdlc            
            isdn switch-type primary-ni            
            isdn protocol-emulate network            
            isdn incoming-voice voice            
            trunk-group PRI            
            no cdp tlv app
            
            
            dial-peer voice 9 pots            
            trunkgroup PRI            
            destination-pattern ^10$            
            forward-digits all
            
            
            *** Add the LPCOR configuration under the ephone profile *****
                        
            ephone  1            
            lpcor type local            
            lpcor incoming PRI            
            description YU CIPC            
            mac-address 507B.9DA2.F72D            
            type CIPC            
            button  1:1            
                         
            ** Add the LPCOR configuration under the voice register pool profile ***
            
                         
            voice register pool  1            
            lpcor type local            
            lpcor incoming PRI            
            busy-trigger-per-button 2            
            id mac 009E.1EDE.A297            
            type 7841            
            number 1 dn 1            
            number 2 dn 2            
            dtmf-relay rtp-nte sip-notify            
            username cusco password adg            
            codec g711ulaw            
            no vad
 
 
                    """
            T.insert(END, lpcor_config)


        elif user_choice == "Extension Mobility for SIP and SCCP":
            extension_mobility = """
            
            EXTENSION MOBILITY FOR SIP AND SCCP PHONES
            

            SIP EM 
            
            ip http server            
            voice register global            
              url authentication http://CME_IP/CCMCIP/authenticate.asp
            
                         
            voice logout-profile 1            
            user cisco password adj            
            number 100
            
                                     
            "Even though the dn will not be assigned anywhere, it needs to be created. If the dn is missing, you'd still be able to log in the user profile, but the phone will not have a number."
            
            voice register dn  1            
            number 100
                                     
            voice register pool  1           
            logout-profile 1            
            id mac F8A5.C59D.DB3C            
            type 8851            
            dtmf-relay rtp-nte            
            codec g711ulaw            
            no vad
                                     
            voice user-profile 1            
            user cisco password adj            
            number 101
                                     
            voice register dn  2            
            number 101
                                     
            voice register global            
            create profile
            
                                                  
            SCCP EM
                         
            
            ip http server
                                     
            telephony-service            
            authentication credential test test            
            max-ephones 10            
            max-dn 10            
            ip source-address 10.63.105.36 port 2000            
            service phone webAccess 0            
            url authentication http://CME_IP/CCMCIP/authenticate.asp test test
                                     
            voice logout-profile 2            
            user cisco password cisco            
            number 200
                                     
            ephone-dn  1            
            number 200
                                     
            ephone  1            
            mac-address 94D4.692A.220C            
            type 7965           
            logout-profile 2
                                   
            voice user-profile 2           
            user panda password adj           
            number 201
                                     
            ephone-dn  2            
            number 201
                                    
            telephony-service           
            create cnf-files
            
                                                  
            "A user can log into a SIP and SCCP phone as long as the number for the user-profile has voice register dn an ephone-dn configured.                                    
            The SIP config can work without the SCCP config and vice versa."
                                    
                                     
            "Admin guide for EM - https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucme/admin/configuration/manual/cmeadm/cmemobl.html"


                    """
            T.insert(END, extension_mobility)


        elif user_choice == "Access List on a Switch for SRST":
            access_list_srst = """

            CONFIGURING AN ACCESS LIST ON A SWITCH FOR TESTING OUT SRST FOR SINGLE OR MULTIPLE PHONES            

            10.56.1.1  -  "(Phone)"
            10.51.17.100  -  "(CUCM)"        
            10.51.17.101  -  "(CUCM 2)"
            
            "130 is the phone's voice vlan"
            
            ----                        
            
            ip access-list extended SRST            
            permit ip host 10.56.1.1 host 10.51.17.100            
            permit ip host 10.56.1.1 host 10.51.17.101                         
            
            permit ip host 10.51.17.100 host 10.56.1.1            
            permit ip host 10.51.17.101 host 10.56.1.1
                                     
            vlan access-map block 10            
            match ip address SRST           
            action drop
                                     
            vlan access-map block 20            
            action forward
                                     
            vlan filter block vlan-list 130
                                     
            ----
                                     


                    """
            T.insert(END, access_list_srst)

choices = ["SIP Trunk with CUCM", "Register SCCP Gateway in CUCM", "H323 Gateway (with CUCM)",
           "SIP CME", "SCCP CME",
           "Gatekeeper Configuration",
           "Embedded Packet Capture", "Packet Capture", "Packet Capture on Processor level", "PCM Capture", "Triggered PCM Capture",
           "Standard ISDN Configuration", "MGCP E1 Configuration", "T1 CAS Configuration",
           "PRI/ISDN Shutdown Bug (errors on interface)",
           "CME GUI", "CUE GUI",
           "DSPFARM Configuration with Gateway", "Conferencing (Ad Hoc / Meet Me)", "DSPFARM with CUCM",
           "Phone Firmware Configuration",
           "Paging Configuration (SCCP)", "Speed Dial SCCP Phones", "CME Night Service", "B-ACD",
           "Hunt Group (Normal)", "Hunt Group (Simultaneous)", "Call Forwarding", "Call Parking",
           "Transfer call from CME to CUCM",
           "CUE Installation", "CUE Configuration", "MWI CUE",
           "SRST SCCP Configuration", "CME SRST", "MGCP SRST", "SIP SRST",
           "COR List Configuration", "Call Blocking", "Toll Fraud Configuration", "Clear a call",
           "Music On Hold", "Verify IOS Image (MD5)", "Fast Track Configuration", "CPU Spike Script",
           "Test translation rule",
           "4K Packet Capture", "4K ISDN PRI configuraiton", "4K DSP Farm", "License Accept 4K",
           "CUE with CUCM",
           "CUE to Email Notification", "VRF with SIP/H323", "How to collect debugs the right way", "MWI with QSIG",
           "Upgrade DSP Firmware", "Reset DSP", "Modem Passthrough with SIP, SCCP and MGCP Gateways",
           "EEM Script - Automatic Packet Capture When IP SLA goes down", "Voiceview express", "Fax Configuration",
           "Span port configuration on a switch", "LPCOR Configuration", "Extension Mobility for SIP and SCCP",
           "Access List on a Switch for SRST"]

#CREATE A VARIABLE FOR THE TKINTER APP

root = Tk()

search_var = tkinter.StringVar()

# CREATE A TEXTBOX AND A SCROLLBAR

S = Scrollbar(root)
T = Text(root, height=30, width=100, background="#141716", highlightbackground="grey", font="TimesNewRoman", wrap=WORD)
S.pack(side=RIGHT, fill=BOTH)
T.pack(side=LEFT, fill=BOTH, expand=1, anchor=W)
S.config(command=T.yview)
T.config(yscrollcommand=S.set, fg = "#82E4D4")

# SET THE LABEL OF THE GUI APPLICATION

ms_label = tkinter.Label(root, text="GDP MS TAC TOOL")
ms_label.pack()
ms_label.config(font=("Arial Black", 20), fg="#627F88")

app = Application(master=root)


# DROP-DOWN MENU SHOW COMMANDS/DEBUGS

# CREATE TKINTER STRING VARIABLE TO STORE THE STRING OUTPUT

var_2 = tkinter.StringVar(root)
var_2.set("Show Commands/Debugs")

choices_2 = ["Show Active Calls", "Show/Debug commands for troubleshooting DSP",
             "Show/Debug commands for troubleshooting Analog devices", "Show/Debug commands for ISDN/PRI",
             "Debug commands for H323", "Show/Debug commands for Gatekeeper", "Show/Debug commands for STC process",
             "Show/Debug commands for Faxing/Modem", "Show/Debug commands for MGCP", "Show commands for CUE with CUCM",
             "Check Dial-Peer match", "Show/Debug for DSP on ISR 2900/3900", "Debug commands for H323",
             "Show/Debug commads for SIP", "Show/Debug commands for SCCP", "Troubleshooting ATA 186",
             "Check if there's a device plugged into an analog port", "Debugs for troubleshooting DTMF",
             "CUE traces for voicemail to email (SMTP)", "CUE traces for backup failure", "Debug for SIP Trunk registration with Telco",
             "Debugs for Extension Mobility"]


def select_2():

    # SETTING THE VARIABLES FOR MATCHING THE USER SELECTION TO THE "if" STATEMENTS
    # WHEN THE USERS MAKES A SELECTION THIS FUNCTION COMPARES THE SELECTION TO THE "if" STATEMENTS.

    show_menu = "%s" % var_2.get()
    root.title(show_menu)
    user_choice_2 = var_2.get()

    if user_choice_2 == "Show Active Calls":
        Show_Active_Calls = """

        show call active voice brief
        show isdn active
        show voice call status
        show voice call summary


        """
        T.insert(END, Show_Active_Calls)

    elif user_choice_2 == "Check Dial-Peer match":
        dial_peer_match = """

        CHECK DIAL-PEER MATCH FOR A DIGIT STRING

        show dialplan number <digit_string>


        """

        T.insert(END, dial_peer_match)

    elif user_choice_2 == "Show/Debug commands for troubleshooting DSP":
        show_dsp = """

        show voice dsp group all 

        debug voip hpi
        debug voice dspapi
        debug voice dsmp
        debug dsp-resource-manager flex


        COLLECT CRASH-DUMP FILE WHEN DSP CRASHES 

        voice dsp crash-dump file-limit <1-99> 
        voice dsp crash-dump destination <url or flash:>

        CRASH DSP 

        Prior to IOS 15.5
        test voice driver
        Enter Voice NM  slot number : 0
        Select option : 10
        Select option : 9
        (1=DSP, 2=ARM) :1
         Enter DSP id : 1
         Enter Mode:
         Mode 1: Simulates Assert Condition
         Mode 2: Simulates Endless loop
         Mode 3: Stop High Level Responses to Commands

         Enter Mode: 3

        In IOS 15.5 and later
        test dsp simulate-crash 0 1 dsp stop-resp


        """
        T.insert(END, show_dsp)

    elif user_choice_2 == "Show/Debug commands for troubleshooting Analog devices":
        show_analog = """

        SHOW ANALOG

        show voice port 
        show voice port summary 
        show voice call summary 
        show call active voice brief 
        show voice dsp detail 
        show voice call status 
        show voice trace <port number>

        DEBUGS ANALOG

        debug voice ccapi inout 
        debug vpm signal  ! 
        debug voip vtsp all 


        """
        T.insert(END, show_analog)

    elif user_choice_2 == "Show/Debug commands for ISDN/PRI":
        show_ISDN = """

        SHOW FOR PRI 

        show network-clocks 
        show isdn status   (isdn layer 2 message should show "MULTIPLE FRAME ESTABLISHED")
        show isdn status detail 
        show isdn service 
        show isdn active
        show controller t1 0/0/0  
        show controller t1 0/0/0  
        show voice dsp group all 
        show voice port summary
        show voice call status 

        DEBUGS FOR ISDN

        debug isdn q931
        debug isdn q921 


        """
        T.insert(END, show_ISDN)
    elif user_choice_2 == "Debug commands for H323":
        debug_h323 = """

        SHOW COMMANDS FOR H323

        debug voip ccapi inout 
        debug h225 q931 
        debug h225 asn1 
        debug h225 events 
        debug h245 asn1 
        debug h245 events

        debug cch323 h225
        debug cch323 h245 


        """
        T.insert(END, debug_h323)

    elif user_choice_2 == "Show/Debug commands for Gatekeeper":
        show_gatekeeper = """

        DEBUGS FOR GATEKEEPER 

        show gateway 
        show h323 gateway 
        show gatekeeper status 
        show gatekeeper calls 
        show gatekeeper end

        debug h225 asn1 
        debug h225 events
        debug cch323 h225 
        debug ip tcp transactions 


        """
        T.insert(END, show_gatekeeper)

    elif user_choice_2 == "Show/Debug commands for Gatekeeper":
        show_gatekeeper = """

        DEBUGS FOR GATEKEEPER 

        show gateway 
        show h323 gateway 
        show gatekeeper status 
        show gatekeeper calls 
        show gatekeeper end

        debug h225 asn1 
        debug h225 events
        debug cch323 h225 
        debug ip tcp transactions 


        """
        T.insert(END, show_gatekeeper)

    elif user_choice_2 == "Show/Debug commands for STC process":
        show_STC = """

        SHOW STC COMMANDS 

        show sccp all 
        show stcapp device summary  - show mac address 
        show stcapp device voice-port 
        show stcapp feature codes 
        show call application voice stcapp 

        DEBUG STC 

        debug voip application stcapp all
        debug sccp events 
        debug sccp messages 
        debug vpm signal  


        """
        T.insert(END, show_STC)

    elif user_choice_2 == "Show/Debug commands for Faxing/Modem":
        show_fax = """

        SHOW AND DEBUG COMMANDS FOR FAXING 

        show call active voice brief 
        show controller t1  (check for slip errors on the controller)
        show fax active voice brief 

        debug voip rtp session named-event 
        debug fax relay t30 all-level-1 

        debug modem relay events


        """
        T.insert(END, show_fax)

    elif user_choice_2 == "Show/Debug commands for MGCP":
        show_MGCP = """

        SHOW AND DEBUG MGCP

        show ccm-manager 
        show isdn status

        debug ccm-manager config download all 
        debug ccm-manager 
        debug mgcp events 
        debug mgcp packets 
        debug isdn q931 
        debug ccm-manager backhaul packets
        
        debug tftp events (check if the MGCP Gateway is downloading its configuraiton successfully)


        """
        T.insert(END, show_MGCP)

    elif user_choice_2 == "Show/Debug commands for MGCP":
        show_MGCP = """

        SHOW AND DEBUG MGCP

        show ccm-manager 
        show isdn status

        debug ccm-manager config download all 
        debug ccm-manager 
        debug mgcp events 
        debug mgcp packets 
        debug isdn q931 
        debug ccm-manager backhaul packets


        """
        T.insert(END, show_MGCP)

    elif user_choice_2 == "Show commands for CUE with CUCM":
        show_CUE_CUCM = """

        CUE with CUCM 

        br2011-cue>show ccn status ccm-manager
        JTAPI Subsystem is currently registered with Call Manager: 14.86.11.11
        JTAPI Version: 3.0(2.3) Release


        """
        T.insert(END, show_CUE_CUCM)

    elif user_choice_2 == "Show/Debug for DSP on ISR 2900/3900":
        show_DSP = """

        SHOW/DEBUG FOR TROUBLESHOOTING DSP ON ISR 2900/3900

        show voice dsp group all
        show diag 

        debug voice ccapi inout
        debug vtsp events
        debug vtsp session
        debug vpm dsp
        debug vpm signal

        ADVANCED DEBUGS:

        debug dsprm all
        debug cdapi events
        debug vtsp all
        debug dspapi all
        debug hpi all
        debug tsp all


        """
        T.insert(END, show_DSP)

    elif user_choice_2 == "Show/Debug for DSP on ISR 2900/3900":
        debug_h323 = """

        SHOW/DEBUG FOR TROUBLESHOOTING H323

        debug voice ccapi inout
        debug h225 q931
        debug h225 asn1
        debug h245 asn1
        debug h225 events
        debug h245 events
        debug ras
        debug ip tcp transactions

        debug cch323 h225
        debug cch323 h245
        debug cch323 session (or "all")


        """
        T.insert(END, debug_h323)

    elif user_choice_2 == "Show/Debug commads for SIP":
        show_sip = """

        SHOW/DEBUG FOR TROUBLESHOOTING SIP

        show sip-ua
        show sip-ua register status


        debug voice ccapi inout

        debug ccsip messages
        debug ccsip errors 
                or 
        debug ccsip all


        """
        T.insert(END, show_sip)

    elif user_choice_2 == "Show/Debug commands for SCCP":
        show_sccp = """

        SHOW/DEBUG FOR TROUBLESHOOTING SCCP

        show stcapp device summary

        debug voip application stcapp port [voice-port number]
        debug sccp event
        debug sccp config

        debug sccp message
        debug voip application stcapp all
        

        """
        T.insert(END, show_sccp)

    elif user_choice_2 == "Troubleshooting ATA 186":
        troubleshooting_ata_186 = """

        TROUBLESHOOTING ATA 186

        1. Capture a snapshot of ATA / 7905 / 7912 Administration web page
        2. Enable appropriate SIP/H323 debugs
        3. Collect ATA / 7905 / 7912 logs using prserv.exe tool
            3.1 Download "prserv" tool to a PC.
            3.2 Set "NPrintf" configuration parameter in Administration web page to the IP address of the PC and an available port. Format: <IP address>.<port>
            3.3 Set "traceFlags" configuration parameter in Administration web page to '0x00000001'
            3.4 At the DOS prompt of the PC enter:
                C:>prserv <port>

                  As preserv receives debug information from the Cisco ATA, it displays the information on the DOS screen and saves it to the output file. <port>.log
            3.5 Recreate the problem
            3.6 Stop "prserv" by entering Ctrl-C at the DSO prompr and collect the <port>.log file.
        4. For SCCP, collect CallManager detailed traces.


        """
        T.insert(END, troubleshooting_ata_186)

    elif user_choice_2 == "Check if there's a device plugged into an analog port":
        plug_port = """

        CHECK IF THERE'S A DEVICE PLUGGED INTO AN ANALOG PORT OR NOT

        test voice port 0/1/1 si-reg-read 29 1
        show log

        "Values read from SiLabs Codec Chip 3240 connected to DSP 7, channel 0:
        ----------------------------------------------------------------
        Register 29 = 0x00


        The 29 field would show something similar to "0x2E" if there's something plugged into the port. 
        Otherwise it will display "0x00".
        

        """
        T.insert(END, plug_port)

    elif user_choice_2 == "Debugs for troubleshooting DTMF":
        dtmf_debug = """

        DEBUGS FOR TROUBLESHOOTING DTMF

        debug voip ccapi inout
        debug voip vtsp default
        debug voip vtsp session
        debug voip dsm error
        debug voip dsm session
        debug voip dsmp error
        debug voip dsmp session
        debug voip dspapi default
        debug voip hpi default
        debug vpm signal        


        """
        T.insert(END, dtmf_debug)


    elif user_choice_2 == "CUE traces for voicemail to email (SMTP)":
        CUE_SMTP = """

        CUE TRACES FOR TROUBLESHOOTING VOICEMAIL TO EMAIL ISSUES
        
        no trace all
        clear trace
        trace voicemail msgnotif all
        trace configapi smtp debug
        trace entitymanager NotifDevice all     
        trace smtp all
        trace entitymanager NotifSched all
        trace entitymanager NotifDB all
        trace entitymanager NotifProfile all
        
        show trace buffer long


        """
        T.insert(END, CUE_SMTP)

    elif user_choice_2 == "CUE traces for backup failure":
        CUE_backup = """

        CUE TRACES FOR INVESTIGATING BACKUP FAILURE

        no trace all
        clear trace
        trace backuprestore all

        show trace buffer long


        """
        T.insert(END, CUE_backup)



    elif user_choice_2 == "Debug for SIP Trunk registration with Telco":
        debug_sip_trunk = """

        DEBUGS FOR TROUBLESHOOTING SIP TRUNK REGISTRATION WITH THE PROVIDER

        debug ccsip non-call
        
                or
                
        debug ccsip all


        """
        T.insert(END, debug_sip_trunk)


    elif user_choice_2 == "Debugs for Extension Mobility":
        debug_ext_mobility = """

        DEBUGS FOR EXTENSION MOBILITY ISSUES

        Deb ip http all
        Deb voice em-profile


        """
        T.insert(END, debug_ext_mobility)




select_2()

option_2 = tkinter.OptionMenu(root, var_2, *choices_2)
option_2.pack()


# DROP-DOWN MENU Q850 CAUSE CODES

var3 = tkinter.StringVar(root)
var3.set('Choose Q850 Cause Code')
choices_q850 = ["Cause Value=1", "Cause Value=2", "Cause Value=3", "Cause Value=4", "Cause Value=5"
    , "Cause Value=6", "Cause Value=7", "Cause Value=8", "Cause Value=9", "Cause Value=16", "Cause Value=17"
    , "Cause Value=18", "Cause Value=19", "Cause Value=20", "Cause Value=21", "Cause Value=22"
    , "Cause Value=23", "Cause Value=25", "Cause Value=26", "Cause Value=27", "Cause Value=28"
    , "Cause Value=29", "Cause Value=30", "Cause Value=31", "Cause Value=34", "Cause Value=38", "Cause Value=39"
    , "Cause Value=40", "Cause Value=41", "Cause Value=42", "Cause Value=43", "Cause Value=44", "Cause Value=46"
    , "Cause Value=47", "Cause Value=49", "Cause Value=50", "Cause Value=53", "Cause Value=55", "Cause Value=57"
    , "Cause Value=58", "Cause Value=62", "Cause Value=63", "Cause Value=65", "Cause Value=66", "Cause Value=69"
    , "Cause Value=70", "Cause Value=79", "Cause Value=81", "Cause Value=82", "Cause Value=83", "Cause Value=84"
    , "Cause Value=85", "Cause Value=86", "Cause Value=87", "Cause Value=88", "Cause Value=90", "Cause Value=91"
    , "Cause Value=95", "Cause Value=96", "Cause Value=97", "Cause Value=98", "Cause Value=99", "Cause Value=100"
    , "Cause Value=101", "Cause Value=102", "Cause Value=103", "Cause Value=110", "Cause Value=111"
    , "Cause Value=127"]


def q850_func():
    def select_850():
        mf = "Q850 %s" % var3.get()
        root.title(mf)
        user_choice_3 = var3.get()

        if user_choice_3 == "Cause Value=1":
            cause_value_1 = """

                "Cause No. 1 – Unallocated (unassigned) number. This cause indicates that the called party cannot be reached because, although the called party number is in a valid format, it is not currently allocated (assigned)."

                """
            T.insert(END, cause_value_1)

        elif user_choice_3 == "Cause Value=2":
            cause_value_2 = """

                "Cause No. 2 – No route to specified transit network (national use). This cause indicates that the equipment sending this cause has received a request to route the call through a particular transit network which it does not recognize. The equipment sending this cause does not recognize the transit network either because the transit network does not exist or because that particular transit network, while it does exist, does not serve the equipment which is sending this cause. This cause is supported on a network-dependent basis."

                """
            T.insert(END, cause_value_2)


        elif user_choice_3 == "Cause Value=3":
            cause_value_3 = """

                "Cause No. 3 – No route to destination. This cause indicates that the called party cannot be reached because the network through which the call has been routed does not serve the destination desired. This cause is supported on a network-dependent basis."

                """
            T.insert(END, cause_value_3)


        elif user_choice_3 == "Cause Value=4":
            cause_value_4 = """

                "Cause No. 4 – Send special information tone. This cause indicates that the called party cannot be reached for reasons that are of a long term nature and that the special information tone should be returned to the calling party."

                """
            T.insert(END, cause_value_4)


        elif user_choice_3 == "Cause Value=5":
            cause_value_5 = """

                "Cause No. 5 – Misdialled trunk prefix (national use). This cause indicates the erroneous inclusion of a trunk prefix in the called party number."

                """
            T.insert(END, cause_value_5)


        elif user_choice_3 == "Cause Value=6":
            cause_value_6 = """

                "Cause No. 6 – Channel unacceptable. This cause indicates that the channel most recently identified is not acceptable to the sending entity for use in this call."

                """
            T.insert(END, cause_value_6)


        elif user_choice_3 == "Cause Value=7":
            cause_value_7 = """

                "Cause No. 7 – Call awarded and being delivered in an established channel. This cause indicates that the user has been awarded the incoming call, and that the incoming call is being connected to a channel already established to that user for similar calls (e.g. packet-mode X.25 virtual calls)."

                """
            T.insert(END, cause_value_7)


        elif user_choice_3 == "Cause Value=8":
            cause_value_8 = """

                  "Cause No. 8 – Preemption. This cause indicates that the call is being pre-empted."    
                  """
            T.insert(END, cause_value_8)


        elif user_choice_3 == "Cause Value=9":
            cause_value_9 = """

                  "Cause No. 9 – Preemption – circuit reserved for reuse. This cause indicates that the call is being pre-empted and the circuit is reserved for reuse by the pre- empting exchange.")

                  """
            T.insert(END, cause_value_9)


        elif user_choice_3 == "Cause Value=16":
            cause_value_16 = """

                  "Cause No. 16 – Normal call clearing. This cause indicates that the call is being cleared because one of the users involved in the call has requested that the call be cleared. Under normal situations, the source of this cause is not the network."

                  """
            T.insert(END, cause_value_16)


        elif user_choice_3 == "Cause Value=17":
            cause_value_17 = """

                  "Cause No. 17 – User busy. This cause is used to indicate that the called party is unable to accept another call because the user busy condition has been encountered. This cause value may be generated by the called user or by the network. In the case of user determine user busy, it is noted that the user equipment is compatible with the call."

                  """
            T.insert(END, cause_value_17)


        elif user_choice_3 == "Cause Value=18":
            cause_value_18 = """

                  "Cause No. 18 – No user responding. This cause is used when a called party does not respond to a call establishment message with either an alerting or connect indication within the prescribed period of time allocated."

                  """
            T.insert(END, cause_value_18)


        elif user_choice_3 == "Cause Value=19":
            cause_value_19 = """

                  "Cause No. 19 – No answer from user (user alerted). This cause is used when the called party has been alerted but does not respond with a connect indication within a prescribed period of time. NOTE – This cause is not necessarily generated by Q.931 procedures but may be generated by internal network timers."

                  """
            T.insert(END, cause_value_19)


        elif user_choice_3 == "Cause Value=20":
            cause_value_20 = """

                  "Cause No. 20 – Subscriber absent. This cause value is used when a mobile station has logged off, radio contact is not obtained with a mobile station or if a personal telecommunication user is temporarily not addressable at any user- network interface."

                  """
            T.insert(END, cause_value_20)


        elif user_choice_3 == "Cause Value=21":
            cause_value_21 = """

                  "Cause No. 21 – Call rejected. This cause indicates that the equipment sending this cause does not wish to accept this call, although it could have accepted the call because the equipment sending this cause is neither busy nor incompatible. This cause may also be generated by the network, indicating that the call was cleared due to a supplementary service constraint. The diagnostic field may contain additional information about the supplementary service and reason for rejection."

                  """
            T.insert(END, cause_value_21)


        elif user_choice_3 == "Cause Value=22":
            cause_value_22 = """

                  "Cause No. 22 – Number changed. This cause is returned to a calling party when the called party number indicated by the calling party is no longer assigned. The new called party number may optionally be included in the diagnostic field. If a network does not support this cause value, cause No. 1, Unallocated (unassigned) number, shall be used."

                  """
            T.insert(END, cause_value_22)


        elif user_choice_3 == "Cause Value=23":
            cause_value_23 = """

                  "Cause No. 23 – Redirection to new destination. This cause is used by a general ISUP protocol mechanism that can be invoked by an exchange that decides that the call should be set-up to a different called number. Such an exchange can invoke a redirection mechanism, by use of this cause value, to request a preceding exchange involved in the call to route the call to the new number."

                  """
            T.insert(END, cause_value_23)


        elif user_choice_3 == "Cause Value=25":
            cause_value_25 = """

                  "Cause No. 25 – Exchange – routing error. This cause indicates that the destination indicated by the user cannot be reached, because an intermediate exchange has released the call due to reaching a limit in executing the hop counter procedure. This cause is generated by an intermediate node, which when decrementing the hop counter value, gives the result 0."

                  """
            T.insert(END, cause_value_25)


        elif user_choice_3 == "Cause Value=26":
            cause_value_26 = """

                  "Cause No. 26 – Non-selected user clearing. This cause indicates that the user has not been awarded the incoming call."

                  """
            T.insert(END, cause_value_26)


        elif user_choice_3 == "Cause Value=27":
            cause_value_27 = """

                  "Cause No. 27 – Destination out of order. This cause indicates that the destination indicated by the user cannot be reached because the interface to the destination is not functioning correctly. The term 'not functioning correctly' indicates that a signalling message was unable to be delivered to the remote party; e.g. a physical layer or data link layer failure at the remote party, or user equipment off-line."

                  """
            T.insert(END, cause_value_27)


        elif user_choice_3 == "Cause Value=28":
            cause_value_28 = """

                  "Cause No. 28 – Invalid number format (address incomplete). This cause indicates that the called party cannot be reached because the called party number is not in a valid format or is not complete. NOTE – This condition may be determined: – immediately after reception of an end of pulsing (ST) signal; or – on time-out after the last received digit."

                  """
            T.insert(END, cause_value_28)


        elif user_choice_3 == "Cause Value=29":
            cause_value_29 = """

                  "Cause No. 29 – Facility rejected. This cause is returned when a supplementary service requested by the user cannot be provided by the network."

                  """
            T.insert(END, cause_value_29)


        elif user_choice_3 == "Cause Value=30":
            cause_value_30 = """

                  "Cause No. 30 – Response to STATUS ENQUIRY. This cause is included in the STATUS message when the reason for generating the STATUS message was the prior receipt of a STATUS ENQUIRY message."

                  """
            T.insert(END, cause_value_30)


        elif user_choice_3 == "Cause Value=31":
            cause_value_31 = """

                  "Cause No. 31 – Normal, unspecified. This cause is used to report a normal event only when no other cause in the normal class applies."

                  """
            T.insert(END, cause_value_31)


        elif user_choice_3 == "Cause Value=34":
            cause_value_34 = """

                  "Cause No. 34 – No circuit/channel available. This cause indicates that there is no appropriate circuit/channel presently available to handle the call."

                  """
            T.insert(END, cause_value_34)


        elif user_choice_3 == "Cause Value=38":
            cause_value_38 = """

                  "Cause No. 38 – Network out of order. This cause indicates that the network is not functioning correctly and that the condition is likely to last a relatively long period of time; e.g. immediately re-attempting the call is not likely to be successful."

                  """
            T.insert(END, cause_value_38)


        elif user_choice_3 == "Cause Value=39":
            cause_value_39 = """

                  "Cause No. 39 – Permanent frame mode connection out of service. This cause connection is included in a STATUS message to indicate that a permanently established frame mode is out of service (e.g. due to equipment or section failure) (see Annex A/Q.933)."

                  """
            T.insert(END, cause_value_39)


        elif user_choice_3 == "Cause Value=40":
            cause_value_40 = """

                  "Cause No. 40 – Permanent frame mode connection operational. This cause connection is included in a STATUS message to indicate that a permanently established frame mode is operational and capable of carrying user information (see Annex A/Q.933)."

                  """
            T.insert(END, cause_value_40)


        elif user_choice_3 == "Cause Value=41":
            cause_value_41 = """

                  "Cause No. 41 – Temporary failure. This cause indicates that the network is not functioning correctly and that the condition is not likely to last a long period of time; e.g. the user may wish to try another call attempt almost immediately."

                  """
            T.insert(END, cause_value_41)


        elif user_choice_3 == "Cause Value=42":
            cause_value_42 = """

                  "Cause No. 42 – Switching equipment congestion. This cause indicates that the switching equipment generating this cause is experiencing a period of high traffic."

                  """
            T.insert(END, cause_value_42)


        elif user_choice_3 == "Cause Value=43":
            cause_value_43 = """

                  "Cause No. 43 – Access information discarded. This cause indicates that the network could not deliver access information to the remote user as requested, i.e. user-to-user information, low layer compatibility, high layer compatibility, or sub- address, as indicated in the diagnostic. It is noted that the particular type of access information discarded is optionally included in the diagnostic."

                  """
            T.insert(END, cause_value_43)


        elif user_choice_3 == "Cause Value=44":
            cause_value_44 = """

                  "Cause No. 44 – Requested circuit/channel not available. This cause is returned when the circuit or channel indicated by the requesting entity cannot be provided by the other side of the interface."

                  """
            T.insert(END, cause_value_44)


        elif user_choice_3 == "Cause Value=46":
            cause_value_46 = """

                  "Cause No. 46 – Precedence call blocked. This cause indicates that there are no preemptable circuits or that the called user is busy with a call of equal or higher preemptable level."

                  """
            T.insert(END, cause_value_46)


        elif user_choice_3 == "Cause Value=47":
            cause_value_47 = """

                  "Cause No. 47 – Resource unavailable, unspecified. This cause is used to report a resource unavailable event only when no other cause in the resource unavailable class applies."

                  """
            T.insert(END, cause_value_47)


        elif user_choice_3 == "Cause Value=49":
            cause_value_49 = """

                  "Cause No. 49 – Quality of Service not available. This cause is used to report that the requested Quality of Service, as defined in Recommendation X.213, cannot be provided (e.g. throughput or transit delay cannot be supported)."

                  """
            T.insert(END, cause_value_49)


        elif user_choice_3 == "Cause Value=50":
            cause_value_50 = """

                  "Cause No. 50 – Requested facility not subscribed. This cause indicates that the user has requested a supplementary service which is implemented by the equipment which generated this cause, but which the user is not authorized to use."

                  """
            T.insert(END, cause_value_50)


        elif user_choice_3 == "Cause Value=53":
            cause_value_53 = """

                  "Cause No. 53 – Outgoing calls barred within CUG. This cause indicates that although the calling party is a member of the CUG for the outgoing CUG call, outgoing calls are not allowed for this member of the CUG."

                  """
            T.insert(END, cause_value_53)


        elif user_choice_3 == "Cause Value=55":
            cause_value_55 = """

                  "Cause No. 55 – Incoming calls barred within CUG. This cause indicates that although the called party is a member of the CUG for the incoming CUG call, incoming calls are not allowed to this member of the CUG."

                  """
            T.insert(END, cause_value_55)


        elif user_choice_3 == "Cause Value=57":
            cause_value_57 = """

                  "Cause No. 57 – Bearer capability not authorized. This cause indicates that the user has requested a bearer capability which is implemented by the equipment which generated this cause but the user is not authorized to use."

                  """
            T.insert(END, cause_value_57)


        elif user_choice_3 == "Cause Value=58":
            cause_value_58 = """

                  "Cause No. 58 – Bearer capability not presently available. This cause indicates that the user has requested a bearer capability which is implemented by the equipment which generated this cause but which is not available at this time."

                  """
            T.insert(END, cause_value_58)


        elif user_choice_3 == "Cause Value=62":
            cause_value_62 = """

                  "Cause No. 62 – Inconsistency in designated outgoing access information and subscriber class. This cause indicates that there is an inconsistency in the designated outgoing access information and subscriber class."

                  """
            T.insert(END, cause_value_62)


        elif user_choice_3 == "Cause Value=63":
            cause_value_63 = """

                  "Cause No. 63 – Service or option not available, unspecified. This cause is used to report a service or option not available event only when no other cause in the service or option not available class applies."

                  """
            T.insert(END, cause_value_63)


        elif user_choice_3 == "Cause Value=65":
            cause_value_65 = """

                  "Cause No. 65 – Bearer capability not implemented. This cause indicates that the equipment sending this cause does not support the bearer capability requested."

                  """
            T.insert(END, cause_value_65)


        elif user_choice_3 == "Cause Value=66":
            cause_value_66 = """

                  "Cause No. 66 – Channel type not implemented. This cause indicates that the equipment sending this cause does not support the channel type requested."

                  """
            T.insert(END, cause_value_66)


        elif user_choice_3 == "Cause Value=69":
            cause_value_69 = """

                  "Cause No. 69 – Requested facility not implemented. This cause indicates that the equipment sending this cause does not support the requested supplementary service."

                  """
            T.insert(END, cause_value_69)


        elif user_choice_3 == "Cause Value=70":
            cause_value_70 = """

                  "Cause No. 70 – Only restricted digital information bearer capability is available (national use). This cause indicates that the calling party has requested an unrestricted bearer service but that the equipment sending this cause only supports the restricted version of the requested bearer capability."

                  """
            T.insert(END, cause_value_70)


        elif user_choice_3 == "Cause Value=79":
            cause_value_79 = """

                  "Cause No. 79 – Service or option not implemented, unspecified. This cause is used to report a service or option not implemented event only when no other cause in the service or option not implemented class applies."

                  """
            T.insert(END, cause_value_79)


        elif user_choice_3 == "Cause Value=81":
            cause_value_81 = """

                  "Cause No. 81 – Invalid call reference value. This cause indicates that the equipment sending this cause has received a message with a call reference which is not currently in use on the user-network interface."

                  """
            T.insert(END, cause_value_81)


        elif user_choice_3 == "Cause Value=82":
            cause_value_82 = """

                  "Cause No. 82 – Identified channel does not exist. This cause indicates that the equipment sending this cause has received a request to use a channel not activated on the interface for a call. For example, if a user has subscribed to those channels on a primary rate interface numbered from 1 to 12 and the user equipment or the network attempts to use channels 13 through 23, this cause is generated."

                  """
            T.insert(END, cause_value_82)


        elif user_choice_3 == "Cause Value=83":
            cause_value_83 = """

                  "Cause No. 83 – A suspended call exists, but this call identity does not. This cause indicates that a call resume has been attempted with a call identity which differs from that in use for any presently suspended call(s)."

                  """
            T.insert(END, cause_value_83)


        elif user_choice_3 == "Cause Value=84":
            cause_value_84 = """

                  "Cause No. 84 – Call identity in use. This cause indicates that the network has received a call suspended request containing a call identity (including the null call identity) which is already in use for a suspended call within the domain of interfaces over which the call might be resumed."

                  """
            T.insert(END, cause_value_84)


        elif user_choice_3 == "Cause Value=85":
            cause_value_85 = """

                  "Cause No. 85 – No call suspended. This cause indicates that the network has received a call resume request containing a call identity information element which presently does not indicate any suspended call within the domain of interfaces over which calls may be resumed."

                  """
            T.insert(END, cause_value_85)


        elif user_choice_3 == "Cause Value=86":
            cause_value_86 = """

                  "Cause No. 86 – Call having the requested call identity has been cleared. This cause indicates that the network has received a call resume request containing a call identity information element indicating a suspended call that has in the meantime been cleared while suspended (either by network timeout or by the remote user)."

                  """
            T.insert(END, cause_value_86)


        elif user_choice_3 == "Cause Value=87":
            cause_value_87 = """

                  "Cause No. 87 – User not member of CUG. This cause indicates that the called user for the incoming CUG call is not a member of the specified CUG or that the calling user is an ordinary subscriber calling a CUG subscriber."

                  """
            T.insert(END, cause_value_87)


        elif user_choice_3 == "Cause Value=88":
            cause_value_88 = """

                  "Cause No. 88 – Incompatible destination. This cause indicates that the equipment sending this cause has received a request to establish a call which has low layer compatibility, high layer compatibility, or other compatibility attributes (e.g. data rate) which cannot be accommodated."

                  """
            T.insert(END, cause_value_88)


        elif user_choice_3 == "Cause Value=90":
            cause_value_90 = """

                  "Cause No. 90 – Non-existent CUG. This cause indicates that the specified CUG does not exist."    

                  """
            T.insert(END, cause_value_90)


        elif user_choice_3 == "Cause Value=91":
            cause_value_91 = """

                  "Cause No. 91 – Invalid transit network selection (national use). This cause indicates that a transit network identification was received which is of an incorrect format as defined in Annex C/Q.931."

                  """
            T.insert(END, cause_value_91)


        elif user_choice_3 == "Cause Value=95":
            cause_value_95 = """

                  "Cause No. 95 – Invalid message, unspecified. This cause is used to report an invalid message event only when no other cause in the invalid message class applies."

                  """
            T.insert(END, cause_value_95)


        elif user_choice_3 == "Cause Value=96":
            cause_value_96 = """

                  "Cause No. 96 – Mandatory information element is missing. This cause indicates that the equipment sending this cause has received a message which is missing an information element which must be present in the message before that message can be processed."

                  """
            T.insert(END, cause_value_96)


        elif user_choice_3 == "Cause Value=97":
            cause_value_97 = """

                  "Cause No. 97 – Message type non-existent or not implemented. This cause indicates that the equipment sending this cause has received a message with a message type it does not recognize either because this is a message not defined or defined but not imple- mented by the equipment sending this cause."

                  """
            T.insert(END, cause_value_97)


        elif user_choice_3 == "Cause Value=98":
            cause_value_98 = """

                  "Cause No. 98 – Message not compatible with call state or message type non-existent or not implemented. This cause indicates that the equipment sending this cause has received a message such that the procedures do not indicate that this is a permissible message to receive while in the call state, or a STATUS message was received indicating an incompatible call state."

                  """
            T.insert(END, cause_value_98)


        elif user_choice_3 == "Cause Value=99":
            cause_value_99 = """

                  "Cause No. 99 – Information element/parameter non-existent or not implemented. This cause indicates that the equipment sending this cause has received a message which includes information element(s)/parameter(s) not recognized because the information element identifier(s)/parameter name(s) are not defined or are defined but not implemented by the equipment sending the cause. This cause indicates that the information element(s)/parameter(s) were discarded. However, the information element is not required to be present in the message in order for the equipment sending the cause to process the message."

                  """
            T.insert(END, cause_value_99)


        elif user_choice_3 == "Cause Value=100":
            cause_value_100 = """

                  "Cause No. 100 – Invalid information element contents. This cause indicates that the equipment sending this cause has received an information element which it has implemented; however, one or more fields in the information element are coded in such a way which has not been implemented by the equipment sending this cause."

                  """
            T.insert(END, cause_value_100)


        elif user_choice_3 == "Cause Value=101":
            cause_value_101 = """

                  "Cause No. 101 – Message not compatible with call state. This cause indicates that a message has been received which is incompatible with the call state."

                  """
            T.insert(END, cause_value_101)


        elif user_choice_3 == "Cause Value=102":
            cause_value_102 = """

                  "Cause No. 102 – Recovery on timer expiry. This cause indicates that a procedure has been initiated by the expiry of a timer in association with error handling procedures."

                  """
            T.insert(END, cause_value_102)


        elif user_choice_3 == "Cause Value=103":
            cause_value_103 = """

                  "Cause No. 103 – Parameter non-existent or not implemented – passed on (national use). This cause indicates that the equipment sending this cause has received a message which includes parameters not recognized because the parameters are not defined or are defined but not implemented by the equipment sending the cause. The cause indicates that the parameter(s) were ignored. In addition, if the equipment sending this cause is an intermediate point, then this cause indicates that the parameter(s) were passed on unchanged."

                  """
            T.insert(END, cause_value_103)


        elif user_choice_3 == "Cause Value=110":
            cause_value_110 = """

                  "Cause No. 110 – Message with unrecognized parameter discarded. This cause indicates that the equipment sending this cause has discarded a received message which includes a parameter that is not recognized."

                  """
            T.insert(END, cause_value_110)


        elif user_choice_3 == "Cause Value=111":
            cause_value_111 = """

                  "Cause No. 111 – Protocol error, unspecified. This cause is used to report a protocol error event only when no other cause in the protocol error class applies."

                  """
            T.insert(END, cause_value_111)


        elif user_choice_3 == "Cause Value=127":
            cause_value_127 = """

                  "Cause No. 127 – Interworking, unspecified. This cause indicates that there has been interworking with a network which does not provide causes for actions it takes. Thus, the precise cause for a message which is being sent cannot be ascertained."

                  """
            T.insert(END, cause_value_127)

        elif user_choice_3 == "Cause Value=0":
            cause_value_0 = """

                  "Disconnect Cause is 0"


                  """
            T.insert(END, cause_value_0)

    select_850()


q850_func()

# CREATING THE Q850 DROP-DOWN BUTTON

q850_button = tkinter.OptionMenu(root, var3, *choices_q850)
q850_button.pack()


# DROP-DOWN MENU CALL FLOW/SIGNALING

var_4 = tkinter.StringVar(root)
var_4.set("Call Flows and Signaling")

choices_4 = ["H323 to ISDN (Slow Start)", "H323 Fast Start", "SIP to ISDN (Delayed Offer)", "SIP to ISDN (Early Offer)",
             "MGCP to ISDN"]

def call_flow():
    cf = "Example signaling for %s" % var_4.get()
    root.title(cf)
    # optional
    user_choice_4 = var_4.get()

    if user_choice_4 == "H323 to ISDN (Slow Start)":
        H323_to_ISDN = """
        
        CUCM ------------------ GATEWAY ------------------ ISDN
        
            Setup --->    
            
            <--- Call Proceeding  
                                                                                Setup --->
                                
                                                                                <--- Call_Proc
                                                            
                                                                                <--- Alerting
                                            
            <--- Alerting
            
            <--- TCS Request
            
            <--- Master Slave Determination
            
            TCS Request --->
            
            <--- TCS ACK
            
            TCS ACK --->
            
            Master Slave Determ ACK --->
            
            <--- Master Slave Determ ACK
            
            <--- Open Logical Channel Request 
            
            Open Logical CHannel Request --->
            
            <--- Open Logical Channel ACK
            
            Open Logical Channel ACK --->
            
                                                                                <--- Connect
                                                            
                                                                                Connect_Ack --->
            <--- Connect
 
            
        """
        T.insert(END, H323_to_ISDN)

    elif user_choice_4 == "SIP to ISDN (Delayed Offer)":
        SIP_to_ISDN = """

        CUCM ------------------ GATEWAY ------------------ ISDN

            INVITE --->    

            <--- Trying  
                                                                                Setup --->

                                                                                <--- Call_Proc

                                                                                <--- Alerting

            <--- 183 Session Progress with SDP

                                                                                <--- Connect

                                                                                Connect_Ack --->
            <--- 200 OK with SDP
            
            ACK with SDP --->
            

        """
        T.insert(END, SIP_to_ISDN)

    elif user_choice_4 == "SIP to ISDN (Early Offer)":
        SIP_to_ISDN_early = """

        CUCM ------------------ GATEWAY ------------------ ISDN

            INVITE with SDP --->    

            <--- Trying  
                                                                                Setup --->

                                                                                <--- Call_Proc

                                                                                <--- Alerting

            <--- 180 Ringing

                                                                                <--- Connect

                                                                                Connect_Ack --->
            <--- 200 OK with SDP

            ACK --->


        """
        T.insert(END, SIP_to_ISDN_early)

    elif user_choice_4 == "MGCP to ISDN":
        MGCP_ISDN = """

        CUCM ------------------ GATEWAY ------------------ ISDN

            CRCX --->    

            <--- 200 OK  
                                                                                Setup --->

                                                                                <--- Call_Proc

                                                                                <--- Alerting

            MDCX --->
            
            <--- 200 OK
            
                                                                                <--- Connect

                                                                                Connect_Ack --->


        """
        T.insert(END, MGCP_ISDN)


    elif user_choice_4 == "H323 Fast Start":
        H323_fast = """
        
        You would be able to see the "fastStart" element in both the Setup and the Connect message.
        

        GATEWAY --------------------------------------------------- CUCM 

            Open Logical Channel (H245) --->    

            Open Logical CHannel (H245) --->  
                                                                
            Setup --->
            
                                                                                                <--- Call Proceeding

                                                                                                <--- Alerting

                                                                                                <--- Connect


        """
        T.insert(END, H323_fast)


call_flow()

# CREATING THE CALL FLOWS/SIGNALING DROP-DOWN BUTTON

option_4 = tkinter.OptionMenu(root, var_4, *choices_4)
option_4.pack()


# TO PRINT THE USER-SELECTED OUTPUT FROM ALL THE DROP-DOWN MENUS IN THE TEXTBOX

def option_changed_2(*args):
    print("{}".format(var_2.get()))
    print(select_2())

var_2.trace("w", option_changed_2)


def option_changed_3(*args):
    print("Disconnect {}".format(var3.get()))
    print(q850_func())

var3.trace("w", option_changed_3)


def option_changed_4(*args):
    print("{}".format(var_4.get()))
    print(call_flow())

var_4.trace("w", option_changed_4)

# CREATE A FUNCTION WHICH WOULD BE USED BY THE "CLEAR" BUTTON

def clear_window():
    T.delete('1.0', END)

# CREATE THE "CLEAR" BUTTON WHICH WOULD DELETE WHATEVER IS IN THE TEXT BOX

Clear_button = tkinter.Radiobutton(root, text="Clear Window", command=clear_window, background="#D1E4EC",
                                   font=("Helvetica", 17), padx=72, pady=19, indicatoron=0)

# HIGHLIGHTING THE "CLEAR" BUTTON WHEN HOVERING OVER IT WITH THE MOUSE

Clear_button.bind("<Enter>", lambda event: Clear_button.configure(bg="#627F88"))
Clear_button.bind("<Leave>", lambda event: Clear_button.configure(bg="#D1E4EC"))

Clear_button.pack(side=BOTTOM, anchor=CENTER)

Clear_button.invoke()

# SAVE AND OPEN BUTTONS CONFIGURATION

def file_save():
    f = filedialog.asksaveasfile(mode='w', defaultextension=".txt")
    if f is None:  # IF FILE IS EMPTY OR THE USER HITS "CANCEL"
        return
    text2save = str(T.get(1.0, "end-1c"))  # starts from `1.0`, not `0.0`
    f.write(text2save)
    f.close()


def file_open():
    Tk().withdraw()
    filename_2 = filedialog.askopenfilename()
    root.title(filename_2)
    with open(filename_2) as o:
        for lines in o:
            print("\n \n" + lines)
            T.insert(INSERT, lines) # THIS WILL INSERT THE PRINTED OUTPUT TO THE TEXT BOX AS WELL

    if filename_2 is None:  # RETURN "NONE" IF THE USER HITS "CANCEL"
        return

# CREATE THE BUTTONS FOR SAVE AND OPEN CONFIGURATION

save_button = Button(root, text="Save Configuration", command=lambda: file_save())
save_button.pack()

open_button = tkinter.Button(root, text="Open Configuration", command=lambda: file_open())
open_button.pack()

root.title("GDP MS TAC TOOL")

app.mainloop()

