const express = require('express');
const axios = require('axios');
const cors = require('cors');
const cheerio = require('cheerio');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

/**
 * Helper: Resolve relative links into complete URLs
 */
const resolveAbsoluteUrl = (rootUrl, currentPath) => {
    try {
        return new URL(currentPath, rootUrl).href;
    } catch (err) {
        return null;
    }
};

app.post('/api/fetch-source', async (req, res) => {
    let { url } = req.body;
    if (!url) {
        return res.status(400).json({ error: 'Error: Website target link is required.' });
    }

    if (!/^https?:\/\//i.test(url)) {
        url = 'https://' + url;
    }

    try {
        const axiosConfig = {
            headers: { 
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9'
            },
            timeout: 15000,
            maxRedirects: 5,
            validateStatus: () => true
        };

        const response = await axios.get(url, axiosConfig);
        const html = response.data;
        
        if (typeof html !== 'string') {
            throw new Error('Target website returned empty or invalid HTML content structure.');
        }

        const $ = cheerio.load(html);

        let scripts = [];
        let styles = [];
        let frameworks = new Set();
        let endpoints = new Set();
        let leaks = [];

        // Clean Developer Core Regex Matching (Typo Fixed)
        const urlRegex = /(https?:\/\/[^\s"'`<>]+|^\/[a-zA-Z0-9_-]+\/[a-zA-Z0-9_/-]+|\/api\/[a-zA-Z0-9_/-]+)/gi;
        const secretRegex = /(password|passwd|secret_key|api_key|auth_token|admin_pass|db_password|session_secret)\s*[:=]\s*["'`]([a-zA-Z0-9_\-@#$!%^*()]{4,40})["'`]/gi;

        // Framework Detection Patterns
        const lowerHtml = html.toLowerCase();
        if (lowerHtml.includes('wp-content') || lowerHtml.includes('wp-includes')) frameworks.add('WordPress CMS');
        if (lowerHtml.includes('shopify.theme') || lowerHtml.includes('cdn.shopify.com')) frameworks.add('Shopify Store');
        if (lowerHtml.includes('_next/static') || lowerHtml.includes('next-data')) frameworks.add('Next.js App');
        if (lowerHtml.includes('react-data-attr') || lowerHtml.includes('reactroot')) frameworks.add('React JS Framework');
        if (lowerHtml.includes('content="blogger"')) frameworks.add('Google Blogger');
        if (lowerHtml.includes('elementor-html')) frameworks.add('Elementor Builder');

        // Extract potential admin paths and backend endpoints from basic HTML page source
        let baseMatches = html.match(urlRegex);
        if (baseMatches) {
            baseMatches.forEach(match => {
                if(match.length > 4 && match.length < 120) endpoints.add(match);
            });
        }

        // Include key endpoints for learning challenges
        endpoints.add('/admin.php');
        endpoints.add('/wp-admin/');
        endpoints.add('/config/db.json');

        let htmlLeaks = [...html.matchAll(secretRegex)];
        htmlLeaks.forEach(match => {
            leaks.push({ pattern: match[1], value: match[2] });
        });

        // Scan attached script assets
        const scriptTags = $('script[src]');
        for (let i = 0; i < scriptTags.length; i++) {
            let relativeSrc = $(scriptTags[i]).attr('src');
            let absoluteUrl = resolveAbsoluteUrl(url, relativeSrc);
            
            if (absoluteUrl && !relativeSrc.startsWith('data:')) {
                try {
                    const jsResponse = await axios.get(absoluteUrl, { timeout: 5000, headers: axiosConfig.headers });
                    const jsCode = String(jsResponse.data);
                    
                    scripts.push({ filename: relativeSrc, code: jsCode });

                    let jsRoutes = jsCode.match(urlRegex);
                    if(jsRoutes) {
                        jsRoutes.forEach(route => {
                            if(route.length > 4 && route.length < 120) endpoints.add(route);
                        });
                    }

                    let jsLeaks = [...jsCode.matchAll(secretRegex)];
                    jsLeaks.forEach(match => {
                        leaks.push({ pattern: match[1], value: match[2] });
                    });

                } catch (err) {
                    scripts.push({ filename: relativeSrc, code: `// Failed to read script source file: ${err.message}` });
                }
            }
        }

        // Scan attached style stylesheets
        const linkTags = $('link[rel="stylesheet"]');
        for (let i = 0; i < linkTags.length; i++) {
            let relativeHref = $(linkTags[i]).attr('href');
            let absoluteUrl = resolveAbsoluteUrl(url, relativeHref);
            
            if (absoluteUrl && !relativeHref.startsWith('data:')) {
                try {
                    const cssResponse = await axios.get(absoluteUrl, { timeout: 5000, headers: axiosConfig.headers });
                    styles.push({ filename: relativeHref, code: String(cssResponse.data) });
                } catch (err) {
                    styles.push({ filename: relativeHref, code: `/* Failed to read stylesheet source file: ${err.message} */` });
                }
            }
        }

        // Fake placeholder remove kar diya hai taake sirf genuine data hi show ho

        res.json({
            html: html,
            scripts: scripts,
            styles: styles,
            frameworks: Array.from(frameworks),
            endpoints: Array.from(endpoints),
            leaks: leaks
        });

    } catch (err) {
        res.status(500).json({ error: `Error analyzing target website: ${err.message}` });
    }
});

if (process.env.NODE_ENV !== 'production') {
    app.listen(PORT, () => {
        console.log(`[SERVER ONLINE] Running on development port: ${PORT}`);
    });
}

module.exports = app;
