# SSO Testing Guide

This guide explains how to test Single Sign-On (SSO) functionality without deploying multiple applications.

## Overview

The SSO test suite simulates multiple applications authenticating against the same Keycloak realm to verify that Single Sign-On works correctly.

### What is SSO?

**Single Sign-On (SSO)** allows users to log in once and gain access to multiple applications without re-entering credentials.

**How it works:**
1. User logs into **Application A** → Keycloak creates SSO session
2. User visits **Application B** → Redirects to Keycloak
3. Keycloak detects existing session → Auto-issues tokens for App B
4. User is now logged into both apps with single login!

## Test Files

### 1. Main Test Dashboard (`test_sso.php`)

The primary interface for SSO testing.

**Features:**
- Visual representation of two applications (App A & App B)
- Real-time status of authentication state
- Interactive SSO flow testing
- Configuration display

**Access:** `http://localhost/keycloak-simss-connector/test_sso.php`

---

### 2. Application A (`test_sso_app_a.php`)

Simulates the first application where user performs initial login.

**Purpose:**
- Handles Keycloak authentication flow
- Creates SSO session
- Stores user tokens

---

### 3. Application B (`test_sso_app_b.php`)

Simulates a second application that leverages SSO.

**Purpose:**
- Tests automatic authentication via SSO
- Verifies no credentials are required if SSO session exists
- Opens in popup window to simulate separate app

---

### 4. Advanced Tests (`test_sso_advanced.php`)

Automated test suite for comprehensive SSO validation.

**Tests:**
1. **Keycloak Session Cookie Detection** - Verifies SSO cookie exists
2. **Silent Authentication** - Tests `prompt=none` functionality
3. **Token Refresh** - Validates refresh token flow
4. **Single Logout** - Checks logout propagation

---

### 5. Session Check API (`test_sso_check_session.php`)

JSON API endpoint for checking session status.

**Returns:**
```json
{
  "session_exists": true,
  "session_id": "abc123...",
  "user": {
    "username": "john.doe",
    "email": "john@example.com"
  },
  "tokens": {
    "has_access_token": true,
    "has_refresh_token": true,
    "has_id_token": true
  }
}
```

---

## How to Test SSO

### Prerequisites

1. **Keycloak Server Running**
   ```bash
   # Verify Keycloak is accessible
   curl https://your-keycloak-server.com/realms/your-realm
   ```

2. **Configuration File**
   ```bash
   # Copy example config
   cp config/keycloak.example.php config/keycloak.php

   # Edit with your Keycloak settings
   nano config/keycloak.php
   ```

3. **Web Server**
   - Apache/Nginx configured
   - PHP 7.1+ installed
   - Composer dependencies installed

### Step-by-Step Testing

#### Test 1: Basic SSO Flow

1. **Open Main Dashboard**
   ```
   http://localhost/keycloak-simss-connector/test_sso.php
   ```

2. **Login to Application A**
   - Click "Login to App A"
   - You'll be redirected to Keycloak
   - Enter your credentials
   - Complete authentication

3. **Verify App A Status**
   - After redirect, App A should show "✓ Logged In"
   - User information should be displayed
   - Session ID should be visible

4. **Test SSO with Application B**
   - Click "Test SSO Login to App B"
   - A popup window opens (simulating App B)
   - **Expected:** App B authenticates automatically WITHOUT asking for credentials
   - **This proves SSO is working!**

---

#### Test 2: Silent Authentication

1. **Ensure logged into App A**

2. **Open App B in incognito/private window**
   ```
   http://localhost/keycloak-simss-connector/test_sso_app_b.php
   ```

3. **Expected Behavior:**
   - If same browser session: Auto-login via SSO
   - If different browser/incognito: Requires login (no SSO session)

---

#### Test 3: Single Logout

1. **Login to both App A and App B**

2. **Logout from App A**
   - Click "Logout from App A"
   - This should end Keycloak SSO session

3. **Refresh App B**
   - App B should also be logged out
   - Attempting to access App B should require re-login

---

#### Test 4: Advanced Automated Tests

1. **Open Advanced Test Suite**
   ```
   http://localhost/keycloak-simss-connector/test_sso_advanced.php
   ```

2. **Click "Run All Tests"**

3. **Review Results:**
   - ✓ **Test 1:** Keycloak session cookie detection
   - ✓ **Test 2:** Silent authentication (prompt=none)
   - ✓ **Test 3:** Token refresh across applications
   - ✓ **Test 4:** Single logout propagation

---

## Understanding SSO Cookies

### Keycloak Session Cookie

**Cookie Name:** `KEYCLOAK_SESSION` or `KEYCLOAK_SESSION_LEGACY`

**Domain:** Your Keycloak server domain

**Purpose:** Tracks SSO session across all applications

**Lifespan:** Configured in Keycloak (typically 30-60 minutes)

### Application Session Cookie

**Cookie Name:** `PHPSESSID` (or custom name)

**Domain:** Your application domain

**Purpose:** Stores application-specific session data

**Lifespan:** PHP session configuration

### How They Work Together

1. **Login to App A:**
   - App A creates `PHPSESSID` cookie
   - Keycloak creates `KEYCLOAK_SESSION` cookie

2. **Access App B:**
   - App B doesn't have `PHPSESSID` (not logged in)
   - But browser sends `KEYCLOAK_SESSION` to Keycloak
   - Keycloak recognizes existing session → auto-login
   - App B creates its own `PHPSESSID`

3. **Result:**
   - Both apps have separate session cookies
   - Both apps authenticated via single Keycloak session

---

## Troubleshooting

### SSO Not Working

**Symptom:** App B asks for credentials even after logging into App A

**Possible Causes:**

1. **Different Browser/Incognito Mode**
   - SSO cookies are session-based
   - Incognito mode has separate cookie storage
   - **Solution:** Use same browser window

2. **Cookie Domain Mismatch**
   - Keycloak cookie domain doesn't match app domain
   - **Solution:** Check Keycloak cookie settings

3. **Session Expired**
   - Keycloak SSO session has timed out
   - **Solution:** Check Keycloak session timeout settings

4. **Different Keycloak Realm**
   - Apps are configured for different realms
   - **Solution:** Verify realm configuration

5. **Cookie Blocked**
   - Browser blocking third-party cookies
   - **Solution:** Allow cookies from Keycloak domain

---

### Debugging Steps

#### 1. Check Browser Cookies

**Chrome DevTools:**
```
1. Open DevTools (F12)
2. Go to Application tab
3. Expand Cookies
4. Check for:
   - KEYCLOAK_SESSION (from Keycloak domain)
   - PHPSESSID (from app domain)
```

#### 2. Check Session Status

**Use API Endpoint:**
```bash
curl http://localhost/keycloak-simss-connector/test_sso_check_session.php
```

**Expected Response:**
```json
{
  "session_exists": true,
  "session_id": "abc123...",
  "user": {
    "username": "john.doe"
  }
}
```

#### 3. Enable Debug Logging

**Edit config/keycloak.php:**
```php
$config['keycloak']['log_level'] = 'debug';
```

**Check logs:**
```bash
tail -f /var/log/apache2/error.log
# or
tail -f /var/log/nginx/error.log
```

#### 4. Test Keycloak Directly

**Check if Keycloak is accessible:**
```bash
curl -v https://your-keycloak.com/realms/your-realm/.well-known/openid-configuration
```

#### 5. Verify Token Endpoint

**Test token endpoint:**
```bash
curl -X POST https://your-keycloak.com/realms/your-realm/protocol/openid-connect/token \
  -d "grant_type=password" \
  -d "client_id=your-client" \
  -d "client_secret=your-secret" \
  -d "username=testuser" \
  -d "password=testpass"
```

---

## Common Issues

### Issue: "State mismatch - possible CSRF attack"

**Cause:** Session was cleared between auth request and callback

**Solution:**
- Don't clear cookies during authentication
- Ensure session is maintained throughout flow
- Check session timeout settings

---

### Issue: "No access token available"

**Cause:** Token exchange failed or session cleared

**Solution:**
- Check Keycloak logs for errors
- Verify client secret is correct
- Ensure redirect URI matches configuration

---

### Issue: Popup Blocked

**Cause:** Browser blocking popup window for App B test

**Solution:**
- Allow popups for this site
- Or manually open App B in new tab:
  ```
  http://localhost/keycloak-simss-connector/test_sso_app_b.php
  ```

---

## Security Considerations

### Testing in Production

**⚠️ WARNING:** These test scripts are for development/testing only!

**Never deploy to production because:**
- Debug output exposes sensitive information
- No access controls on test endpoints
- Session manipulation capabilities
- Potential security vulnerabilities

### Removing Test Files

**Before deploying to production:**
```bash
rm test_sso*.php
rm SSO_TESTING_GUIDE.md
```

**Or restrict access:**
```apache
# In .htaccess
<FilesMatch "^test_sso.*\.php$">
    Require ip 127.0.0.1
    Require ip ::1
</FilesMatch>
```

---

## How SSO Actually Works (Technical)

### Step-by-Step Flow

#### Initial Login (App A)

1. **User visits App A** → Not authenticated
2. **App A redirects to Keycloak:**
   ```
   GET /auth?response_type=code&client_id=app-a&redirect_uri=...&state=xyz
   ```
3. **User enters credentials** at Keycloak
4. **Keycloak validates** and creates SSO session
5. **Keycloak sets cookie:** `KEYCLOAK_SESSION=abc123...`
6. **Keycloak redirects back:**
   ```
   GET /callback?code=authcode&state=xyz
   ```
7. **App A exchanges code for tokens:**
   ```
   POST /token
   grant_type=authorization_code
   code=authcode
   ```
8. **Keycloak returns tokens:**
   ```json
   {
     "access_token": "eyJhbG...",
     "refresh_token": "eyJhbG...",
     "id_token": "eyJhbG..."
   }
   ```
9. **App A creates session** and stores tokens

---

#### SSO Login (App B)

1. **User visits App B** → Not authenticated (in App B)
2. **App B redirects to Keycloak:**
   ```
   GET /auth?response_type=code&client_id=app-b&redirect_uri=...&state=abc
   ```
3. **Keycloak receives request** with `KEYCLOAK_SESSION` cookie
4. **Keycloak checks cookie** → Valid session exists!
5. **Keycloak auto-approves** (no login prompt needed)
6. **Keycloak redirects back immediately:**
   ```
   GET /callback?code=authcode2&state=abc
   ```
7. **App B exchanges code for tokens** (same as App A)
8. **App B creates session** and stores tokens

**Result:** User is now logged into both apps with single login!

---

## Next Steps

After verifying SSO works correctly:

1. **Review Security Findings**
   - Read `CODE_REVIEW_FINDINGS.md`
   - Implement critical security fixes

2. **Configure Production Settings**
   - Set proper redirect URIs
   - Configure session timeouts
   - Enable HTTPS enforcement

3. **Test Token Refresh**
   - Verify tokens refresh automatically
   - Test silent SSO re-authentication

4. **Implement Single Logout**
   - Ensure logout works across all apps
   - Test logout URL generation

5. **Performance Testing**
   - Test with multiple concurrent users
   - Monitor token refresh overhead
   - Check permission middleware performance

---

## Resources

- [Keycloak Documentation](https://www.keycloak.org/documentation)
- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [OpenID Connect Specification](https://openid.net/specs/openid-connect-core-1_0.html)
- [Keycloak SSO Configuration](https://www.keycloak.org/docs/latest/server_admin/#sso-protocols)

---

## Support

If you encounter issues:

1. Check this guide's troubleshooting section
2. Review `CODE_REVIEW_FINDINGS.md` for known issues
3. Check Keycloak server logs
4. Verify configuration in `config/keycloak.php`

---

**Last Updated:** 2026-01-02
**Version:** 1.0
