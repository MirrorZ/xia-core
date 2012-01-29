require(library ../../../xia_router_template_xtransport.click);
require(library ../../../xia_address.click);

// host instantiation
host0 :: EndHost (RE AD0 HID0, HID0, fake0,172.0.0.2,172.0.0.1,11:11:11:11:11:11,0);
//router1 :: Router4PortDummyCache(RE AD1 RHID1, AD1, RHID1); // if router does not understand CID pricipal


// Interface0 (eth2)
c0 :: Classifier(12/9990 20/0001, 12/9990 20/0002, 12/9999);  // XARP (query) or XARP (response) or XIP
xarpq0 :: XARPQuerier(HID0, 00:04:23:b7:17:6c);
xarpr0 :: XARPResponder(HID0 00:04:23:b7:17:6c);
todevice0 :: ToDevice(eth2);
fromdevice0 :: FromDevice(eth2, PROMISC true);


// On receiving a packet from Interface0
fromdevice0 -> c0;

// On receiving an XIP packet
c0[2] -> Strip(14) -> MarkXIAHeader() 
-> Print()
-> XIAPrint("r0->h0")
-> [0]host0; // XIA packet

// On receiving XARP response
c0[1] -> [1]xarpq0 -> todevice0;

// On receiving XARP query
c0[0] -> xarpr0 -> todevice0;

// Sending an XIP packet (via XARP if necessary) to Interface0
host0[0]
-> Print()
-> XIAPrint("h0->r0")
-> c::XIAXIDTypeCounter(src AD, src HID, src SID, src CID, src IP, -) 
-> [0]xarpq0
-> todevice0;



ControlSocket(tcp, 7777);

//Script(write gen.active true);  // the packet source should be activated after all other scripts are executed


//Script(write host0/n/proc/rt_HID/rt.add HID0 4);  
//Script(write host0/n/proc/rt_HID/rt.add - 0);    

//Script(write host0/n/proc/rt_AD/rt.add AD0 4);    
//Script(write host0/n/proc/rt_AD/rt.add - 0);   

//Script(write host0/n/proc/rt_SID/rt.add - 5);     // no default route for SID; consider other path
//Script(write host0/n/proc/rt_CID/rt.add - 5);     // no default route for CID; consider other path





