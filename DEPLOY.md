# PlanetScale Deployment Guide

## 1. Setup PlanetScale Database
1. Go to https://planetscale.com
2. Create free account
3. Create new database: `certificate-system`
4. Get connection string from dashboard

## 2. Deploy Options

### Option A: Vercel (Recommended)
1. Push to GitHub
2. Connect Vercel account
3. Add environment variables:
   - `DATABASE_URL`: Your PlanetScale connection string
   - `EMAIL_USER`: mnabhishek99@gmail.com
   - `EMAIL_PASS`: bummxatjzrqkdktd
4. Deploy

### Option B: Railway
1. Push to GitHub
2. Connect Railway
3. Add same environment variables
4. Deploy

### Option C: Render
1. Uses existing render.yaml
2. Add environment variables
3. Deploy

## 3. Access
- URL: Your deployment URL
- Admin: admin/admin123

## 4. Database Setup
Tables auto-create on first run.