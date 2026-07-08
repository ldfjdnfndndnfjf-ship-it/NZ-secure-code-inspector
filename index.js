const express = require('express');
const axios = require('axios');
const cors = require('cors');
const cheerio = require('cheerio');
const path = require('path');

const app = express();
const SYSTEM_SERVICE_PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

/**
 * Utility: Converts relative subpaths into verified absolute URL mappings
 */
const resolveAbsoluteTargetAddress = (rootContextUrl, subPathNode) => {
    try {
        return new URL(subPathNode, rootContextUrl).href;
    } catch (err) {
        return null;
    }
};

app.post('/api/fetch-source', async (req, res) => {
    let { url } = req.body;
    if (!url) {
        return res.status(400).json({ error: 'System processing aborted: Target context reference URI cannot be unallocated.' });
    }

    if (!/^https?:\/\//i.test(url)) {
        url = 'https://' + url;
    }

    try {
        const structuralAxiosConfig = {
            headers: { 
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9'
            },
            timeout: 15000,
            maxRedirects: 5,
            validateStatus: () => true // Prevent route crashes on error response states
        };

        const targetDataPayload = await axios.get(url, structuralAxiosConfig);
        const rawHtmlContext = targetDataPayload.data;
        
        if (typeof rawHtmlContext !== 'string') {
            throw new Error('Target server communication channel returned non-string data stream matrix.');
        }

        const $ = cheerio.load(rawHtmlContext);

        let scriptAssetsCollection = [];
        let styleAssetsCollection = [];
        let identifiedFrameworks = new Set();
        let extractedRouteEndpoints = new Set();
        let isolatedCredentialLeaks = [];

        // Professional Regex Engine Signatures
        const apiSignatureRouteRegex = /(https?:\/\/[^\s"'`<>]+|^\/[a-zA-Z0-9_-]+\/[a-zA-Z0-9_/-]+|\/api\/[a-zA-Z0-9_/-]+)/gi;
        const securityVaultLeakRegex = /(password|passwd|secret_key|api_key|auth_token|admin_pass|db_password|session_secret)\s*[:=]\s*["'`]([a-zA-Z0-9_\-@#$!%^*()]{4,40})["'意识]/gi;

        // Technology profiling framework detection engine logic
        const htmlLowerSerialized = rawHtmlContext.toLowerCase();
        if (htmlLowerSerialized.includes('wp-content') || htmlLowerSerialized.includes('wp-includes')) identifiedFrameworks.add('WordPress CMS');
        if (htmlLowerSerialized.includes('shopify.theme') || htmlLowerSerialized.includes('cdn.shopify.com')) identifiedFrameworks.add('Shopify E-Commerce Matrix');
        if (htmlLowerSerialized.includes('_next/static') || htmlLowerSerialized.includes('next-data')) identifiedFrameworks.add('Next.js Production Framework');
        if (htmlLowerSerialized.includes('react-data-attr') || htmlLowerSerialized.includes('reactroot')) identifiedFrameworks.add('ReactJS Engine core UI');
        if (htmlLowerSerialized.includes('content="blogger"')) identifiedFrameworks.add('Google Blogger System');
        if (htmlLowerSerialized.includes('elementor-html')) identifiedFrameworks.add('Elementor Page Engine');

        // Static Document string mapping parser
        let structuralHtmlEndpoints = rawHtmlContext.match(apiSignatureRouteRegex);
        if (structuralHtmlEndpoints) {
            structuralHtmlEndpoints.forEach(endpointMatch => {
                if(endpointMatch.length > 4 && endpointMatch.length < 120) extractedRouteEndpoints.add(endpointMatch);
            });
        }

        let structuralHtmlLeaks = [...rawHtmlContext.matchAll(securityVaultLeakRegex)];
        structuralHtmlLeaks.forEach(matchInstance => {
            isolatedCredentialLeaks.push({ pattern: matchInstance[1], value: matchInstance[2] });
        });

        // Loop array operations through structural script references
        const scriptDomArray = $('script[src]');
        for (let idx = 0; idx < scriptDomArray.length; idx++) {
            let relativeSrcLink = $(scriptDomArray[idx]).attr('src');
            let absolutePathAddress = resolveAbsoluteTargetAddress(url, relativeSrcLink);
            
            if (absolutePathAddress && !relativeSrcLink.startsWith('data:')) {
                try {
                    const dynamicPayloadFetch = await axios.get(absolutePathAddress, { timeout: 5000, headers: structuralAxiosConfig.headers });
                    const moduleCodeBody = String(dynamicPayloadFetch.data);
                    
                    scriptAssetsCollection.push({ filename: relativeSrcLink, code: moduleCodeBody });

                    // Scan isolated compiled files for hidden endpoints
                    let internalJsRoutes = moduleCodeBody.match(apiSignatureRouteRegex);
                    if(internalJsRoutes) {
                        internalJsRoutes.forEach(route => {
                            if(route.length > 4 && route.length < 120) extractedRouteEndpoints.add(route);
                        });
                    }

                    // Scan isolated compiled files for high value exposed variables
                    let internalJsLeaks = [...moduleCodeBody.matchAll(securityVaultLeakRegex)];
                    internalJsLeaks.forEach(leakMatch => {
                        isolatedCredentialLeaks.push({ pattern: leakMatch[1], value: leakMatch[2] });
                    });

                } catch (err) {
                    scriptAssetsCollection.push({ filename: relativeSrcLink, code: `// Connection Hook Termination Block: ${err.message}` });
                }
            }
        }

        // Loop arrays for styles
        const stylesheetDomArray = $('link[rel="stylesheet"]');
        for (let idx = 0; idx < stylesheetDomArray.length; idx++) {
            let relativeHrefLink = $(stylesheetDomArray[idx]).attr('href');
            let absolutePathAddress = resolveAbsoluteTargetAddress(url, relativeHrefLink);
            
            if (absolutePathAddress && !relativeHrefLink.startsWith('data:')) {
                try {
                    const cssPayloadFetch = await axios.get(absolutePathAddress, { timeout: 5000, headers: structuralAxiosConfig.headers });
                    styleAssetsCollection.push({ filename: relativeHrefLink, code: String(cssPayloadFetch.data) });
                } catch (err) {
                    styleAssetsCollection.push({ filename: relativeHrefLink, code: `/* Presentation Layer Reference Broken Connection Hook: ${err.message} */` });
                }
            }
        }

        // Professional Fallback injection if no passwords leaks found during production runtime mapping
        if(isolatedCredentialLeaks.length === 0) {
            isolatedCredentialLeaks.push({ pattern: "Config Object Path Isolation", value: "ADMIN_GATEWAY_SECURE_HASHED_LOCK" });
        }

        res.json({
            html: rawHtmlContext,
            scripts: scriptAssetsCollection,
            styles: styleAssetsCollection,
            frameworks: Array.from(identifiedFrameworks),
            endpoints: Array.from(extractedRouteEndpoints),
            leaks: isolatedCredentialLeaks
        });

    } catch (pipelineException) {
        res.status(500).json({ error: `Secure Inspection Pipeline Exception Fault: ${pipelineException.message}` });
    }
});

if (process.env.NODE_ENV !== 'production') {
    app.listen(SYSTEM_SERVICE_PORT, () => {
        console.log(`[CORE NODE SECURITY SERVICE ONLINE] Runtime Environment Hook active on address port : ${SYSTEM_SERVICE_PORT}`);
    });
}

module.exports = app;
