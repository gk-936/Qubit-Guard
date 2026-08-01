const { discoverEndpoints } = require('../backend/services/api-scanner');
const { performTriadScan } = require('../backend/services/scanner-engine');

async function testPerfection() {
    const domain = 'manipurrural.bank.in';
    console.log(`--- TESTING PERFECTION FOR ${domain} ---`);
    
    // 1. Test Discovery (Server Fingerprinting)
    const metrics = await discoverEndpoints(domain);
    console.log('\n[DISCOVERY RESULTS]');
    console.log('Total Assets:', metrics.total);
    metrics.details.slice(0, 5).forEach(d => {
        console.log(`- Host: ${d.host} | Server: ${d.server} | Bucket: ${d.bucket}`);
    });

    // 2. Test Triad Scan (Logic Check)
    const triad = await performTriadScan(domain);
    console.log('\n[TRIAD RESULTS]');
    console.log('Web Cert:', triad.findings.web[0]?.issue);
    console.log('Web Server:', triad.findings.web[0]?.raw?.cipher);

    // 3. Synthesis Simulation (Clustering Check)
    const cbomItems = [];
    const hostClusters = {};
    metrics.details.forEach(ep => {
        if (!hostClusters[ep.host]) {
            hostClusters[ep.host] = { host: ep.host, server: ep.server, bucket: ep.bucket };
        }
    });

    Object.values(hostClusters).forEach(cluster => {
        cbomItems.push({
            component: `${cluster.server} Infrastructure Node (${cluster.host})`,
            category: cluster.bucket,
            version: cluster.server,
            quantumSafe: false
        });
    });

    console.log('\n[FINAL CBOM SYNTHESIS]');
    cbomItems.slice(0, 5).forEach(c => {
        console.log(`> Component: ${c.component}`);
    });

    if (cbomItems.some(c => c.component.includes('General API'))) {
        console.log('\n[!] WARNING: Still seeing generic labels!');
    } else {
        console.log('\n[✓] SUCCESS: All components professionally fingerprinted.');
    }
}

testPerfection().catch(err => {
    console.error('Test Failed:', err);
    process.exit(1);
});
