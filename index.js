const Pcap = require('pcap');
const session = Pcap.createSession('', 'arp');
const util = require('util');

const octetsToStr = (arr) => arr.filter(oct => oct > 0).map(oct => oct.toString(16)).join(':');
const oui = (mac) => require('oui')(octetsToStr(mac));

const clean = (pkt) => {
    const decoded = Pcap.decode.packet(pkt);
    const sourceMac = decoded.payload.shost.addr;
    const destMac = decoded.payload.dhost.addr;
    const senderMac = decoded.payload.payload.sender_ha.addr;
    const targetMac = decoded.payload.payload.target_ha.addr;
    return {
        source_mac: sourceMac,
        source_oui: oui(sourceMac),
        dest_mac: decoded.payload.dhost.addr,
        dest_oui: oui(destMac),
        sender_mac: senderMac,
        sender_oui: oui(senderMac),
        sender_ip: decoded.payload.payload.target_pa.addr,
        target_mac: targetMac,
        target_oui: oui(targetMac),
        target_ip: decoded.payload.payload.target_pa.addr
    };
};

session.on('packet', (pkt) => {
    console.log(clean(pkt));
});
