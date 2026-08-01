const { performTriadScan } = require('../backend/services/scanner-engine');
const { analyzeVulnerabilities } = require('../backend/services/ai-service');
const { discoverEndpoints } = require('../backend/services/api-scanner');
const dotenv = require('dotenv');
const path = require('path');

// Load environment from backend
dotenv.config({ path: path.join(__dirname, '../backend/.env') });

async function runAudit(targetUrl) {
    console.log(`--- Qubit-Guard Prototype Audit: ${targetUrl} ---`);
    
    try {
        // 1. Perform Triad Scan (Web/TLS is live, VPN is mocked)
        console.log("\n[1] Running Triad Scan (Web/VPN/API)...");
        const scanResults = await performTriadScan(targetUrl, `vpn.${targetUrl}`, `api.${targetUrl}`, null);
        console.log("Web Findings:", JSON.stringify(scanResults.findings.web, null, 2));
        
        // 2. Discover API Endpoints (Mocked)
        console.log("\n[2] Performing API Endpoint Discovery...");
        const apiMetrics = await discoverEndpoints(targetUrl);
        
        // 3. AI Analysis (LIVE - Sarvam AI)
        console.log("\n[3] Triggering Live Sarvam AI Analysis...");
        const aiAnalysis = await analyzeVulnerabilities({ 
            ...scanResults, 
            apiMetrics 
        });
        
        console.log("\n--- LIVE AI ANALYSIS RESULTS ---");
        console.log("Summary:", aiAnalysis.summary);
        console.log("Risks Detected:", aiAnalysis.risks.join(", "));
        console.log("Technical Suggestions:", JSON.stringify(aiAnalysis.suggestions, null, 2));

        console.log("\n[RESULT] Scan completed successfully. Sarvam AI analysis has replaced the mock logic.");
    } catch (err) {
        console.error("Audit Failed:", err.message);
    }
}

// Run for pnb.bank.in
runAudit('pnb.bank.in');
