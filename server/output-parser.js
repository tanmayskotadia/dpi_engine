/**
 * Parses the stdout text from the C++ DPI engine into a structured JSON object.
 */
function parseEngineOutput(outputText) {
    const lines = outputText.split('\n');
    
    const results = {
        packetStats: {
            totalPackets: 0,
            totalBytes: 0,
            tcpPackets: 0,
            udpPackets: 0
        },
        filteringStats: {
            forwarded: 0,
            dropped: 0,
            dropRate: 0
        },
        threadStats: {
            loadBalancers: [],
            fastPaths: []
        },
        appBreakdown: [],
        detectedDomains: []
    };
    
    let currentSection = '';
    
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        
        if (line.includes('PACKET STATISTICS') || line.includes('Total Packets :')) currentSection = 'packet_stats';
        else if (line.includes('FILTERING STATISTICS') || line.includes('Forwarded     :')) currentSection = 'filtering_stats';
        else if (line.includes('THREAD STATISTICS') || line.includes('LB0 dispatched')) currentSection = 'thread_stats';
        else if (line.includes('APPLICATION BREAKDOWN')) currentSection = 'app_breakdown';
        else if (line.includes('[Detected Domains/SNIs]')) currentSection = 'detected_domains';
        
        // Parse Packet Stats
        if (line.startsWith('Total Packets')) {
            const match = line.match(/:\s*(\d+)/);
            if (match) results.packetStats.totalPackets = parseInt(match[1]);
        }
        else if (line.startsWith('Total Bytes')) {
            const match = line.match(/:\s*(\d+)/);
            if (match) results.packetStats.totalBytes = parseInt(match[1]);
        }
        else if (line.startsWith('TCP Packets')) {
            const match = line.match(/:\s*(\d+)/);
            if (match) results.packetStats.tcpPackets = parseInt(match[1]);
        }
        else if (line.startsWith('UDP Packets')) {
            const match = line.match(/:\s*(\d+)/);
            if (match) results.packetStats.udpPackets = parseInt(match[1]);
        }
        
        // Parse Filtering Stats
        else if (line.startsWith('Forwarded')) {
            const match = line.match(/:\s*(\d+)/);
            if (match) results.filteringStats.forwarded = parseInt(match[1]);
        }
        else if (line.startsWith('Dropped')) {
            const match = line.match(/:\s*(\d+)/);
            if (match) results.filteringStats.dropped = parseInt(match[1]);
        }
        
        // Parse Thread Stats
        else if (line.match(/^LB(\d+)\s+dispatched\s*:\s*(\d+)/)) {
            const match = line.match(/^LB(\d+)\s+dispatched\s*:\s*(\d+)/);
            results.threadStats.loadBalancers.push({
                id: parseInt(match[1]),
                dispatched: parseInt(match[2])
            });
        }
        else if (line.match(/^FP(\d+)\s+processed\s*:\s*(\d+)/)) {
            const match = line.match(/^FP(\d+)\s+processed\s*:\s*(\d+)/);
            results.threadStats.fastPaths.push({
                id: parseInt(match[1]),
                processed: parseInt(match[2])
            });
        }
        
        // Parse Application Breakdown
        else if (currentSection === 'app_breakdown' && line && !line.includes('---') && !line.includes('===') && !line.includes('APPLICATION')) {
            // Expected format: "App Name        Count    Pct%   #####"
            // Let's use a regex to capture it. 
            // The C++ code outputs: std::setw(15) << app << std::setw(8) << count << "  " << pct << "% " << bar
            
            // Simple split by multiple spaces won't work well if app name has spaces, but app names here are single words mostly.
            // Let's look for the % sign.
            const pctMatch = line.match(/([\d\.]+)%/);
            if (pctMatch) {
                const parts = line.trim().split(/\s{2,}/); // split by 2 or more spaces
                if (parts.length >= 3) {
                    const app = parts[0].trim();
                    const countStr = parts[1].trim();
                    // If the number somehow stuck to the app name
                    const count = parseInt(countStr);
                    const percentage = parseFloat(pctMatch[1]);
                    
                    if (app && !isNaN(count)) {
                        results.appBreakdown.push({
                            app: app,
                            count: count,
                            percentage: percentage
                        });
                    }
                }
            }
        }
        
        // Parse Detected Domains
        else if (currentSection === 'detected_domains' && line.startsWith('-')) {
            // Format: "- domain.com -> AppType"
            const match = line.match(/-\s+(.*?)\s+->\s+(.*)/);
            if (match) {
                results.detectedDomains.push({
                    sni: match[1].trim(),
                    app: match[2].trim()
                });
            }
        }
    }
    
    // Calculate drop rate if not parsed
    if (results.packetStats.totalPackets > 0) {
        results.filteringStats.dropRate = (results.filteringStats.dropped / results.packetStats.totalPackets) * 100;
    }
    
    return results;
}

module.exports = { parseEngineOutput };
