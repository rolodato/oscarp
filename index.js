const Pcap = require('pcap');
const nmap = require('libnmap');
const osc = require('osc');
const os = require('os');
const ip = require('ip');
const Rx = require('rx');

const interfaceName = process.env.IFACE;
const interfaces = Object.keys(os.networkInterfaces());
if (!interfaceName) {
    throw `No network interface configured. Make sure $IFACE is set to one of: ${interfaces}`;
}
console.log(`Using interface ${interfaceName}`);
const interface = os.networkInterfaces()[interfaceName][0];
if (!interface) {
    throw `Could not find interface ${interfaceName}`;
}
const subnet = ip.subnet(interface.address, interface.netmask);
const range = subnet.networkAddress + '/' + subnet.subnetMaskLength;
const scan = () => {
    console.log('Beginning ARP scan on ' + range);
    nmap.scan({
        threshold: 1, // prevent "Callback was already called" error
        range: [range]
    }, (err, res) => {
        res.forEach(r => console.log(JSON.stringify(r, null, 2)));
        scan();
    });
};
scan();

const octetsToStr = (arr) => arr.filter(oct => oct > 0).map(oct => oct.toString(16)).join(':');

const manufacturer = (mac) => (require('oui')(octetsToStr(mac)) || '').split('\n')[0];

const clean = (pkt) => {
    const payload = Pcap.decode.packet(pkt).payload;
    const sourceMac = payload.shost.addr;
    const destMac = payload.dhost.addr;
    const senderMac = payload.payload.sender_ha.addr;
    const targetMac = payload.payload.target_ha.addr;
    return {
        source_mac: sourceMac,
        source_oui: manufacturer(sourceMac),
        dest_mac: payload.dhost.addr,
        dest_oui: manufacturer(destMac),
        sender_mac: senderMac,
        sender_oui: manufacturer(senderMac),
        sender_ip: payload.payload.target_pa.addr,
        target_mac: targetMac,
        target_oui: manufacturer(targetMac),
        target_ip: payload.payload.target_pa.addr
    };
};

const udpPort = new osc.UDPPort({
    localAddress: '0.0.0.0',
    localPort: 27015,
    remoteAddress: '127.0.0.1',
    remotePort: 27016
});
udpPort.open();

const pairToOsc = (pair) => {
    return {
        address: '/' + pair[0],
        args: pair[1]
    };
};

const delay = Rx.Observable.empty().delay(50);

const session = Pcap.createSession('', 'arp');
Rx.Observable
    .fromEvent(session, 'packet') // raw packet stream
    .map(clean) // pick and flatten packet
    .flatMap(pkt => Rx.Observable.pairs(pkt)) // separate packet properties into kv pairs
    .map(pairToOsc)
    .map(osc => Rx.Observable.return(osc).concat(delay)) // buffer each kv pair to avoid flooding destination
    .concatAll()
    .do(console.log)
    .subscribe(osc => udpPort.send(osc));
