# 🛡️ CyberSec Academy — 31-Day Vulnerability Tracker

A full-stack web app to track your cybersecurity learning journey from **June 24 to July 24, 2026**.

## Features
- 31 days × advanced vulnerabilities (SSRF, XXE, Deserialization, JWT, SSTI, Race Conditions, etc.)
- Checkbox progress tracking with persistent database
- 5-question quiz per day with scoring
- Full scorecard at end
- Dark/Light mode
- Mobile responsive
- Persistent storage (JSON database on server)

## Deploy to Render (Free)

### Step 1: Push to GitHub
```bash
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/YOUR_USERNAME/cybersec-tracker.git
git push -u origin main
```

### Step 2: Deploy on Render
1. Go to [render.com](https://render.com) → Sign up/Login
2. Click **New** → **Web Service**
3. Connect your GitHub repo
4. Settings:
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
   - **Plan**: Free
5. Click **Deploy**

Your site will be live at: `https://cybersec-tracker.onrender.com`

## Local Development
```bash
npm install
npm start
# Visit http://localhost:3000
```

## Tech Stack
- **Backend**: Node.js + Express
- **Database**: lowdb (JSON file — persists data on Render's disk)
- **Frontend**: Vanilla HTML/CSS/JS (no framework needed)
- **Fonts**: Orbitron + Rajdhani + Share Tech Mono

## Vulnerabilities Covered (31 Days)
1. SSRF | 2. XXE | 3. Insecure Deserialization | 4. HTTP Request Smuggling
5. SSTI | 6. Race Conditions | 7. OAuth 2.0 | 8. WebSockets
9. GraphQL | 10. JWT | 11. Mass Assignment | 12. Business Logic
13. File Upload | 14. Path Traversal | 15. LDAP Injection | 16. Subdomain Takeover
17. NoSQL Injection | 18. Prototype Pollution | 19. HTTP Response Splitting
20. DNS Rebinding | 21. Cache Poisoning | 22. Log Injection (Log4Shell)
23. WebAssembly | 24. Clickjacking | 25. Advanced IDOR Chains
26. Dependency Confusion | 27. Secret Exposure | 28. Kubernetes Security
29. Advanced Blind SQLi | 30. DOM Clobbering | 31. Bug Bounty Methodology
