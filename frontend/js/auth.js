// ─────────────────────────────────────────────
// auth.js  -  Complete authentication logic
// Email/password + Google OAuth
// SendGrid emails via backend
// 30-minute session timeout
// ─────────────────────────────────────────────

import { auth } from './firebase-config.js';
import {
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  onAuthStateChanged,
  signOut,
  browserLocalPersistence,
  setPersistence,
  GoogleAuthProvider,
  signInWithPopup
} from 'https://www.gstatic.com/firebasejs/10.12.0/firebase-auth.js';

// ─────────────────────────────────────────────
// CONFIG
// ─────────────────────────────────────────────

const API          = 'https://cybershield-backend-irzr.onrender.com/api';
const SESSION_MS   = 30 * 60 * 1000;   // 30 minutes
const ACTIVITY_KEY = 'cs_last_activity';

// ─────────────────────────────────────────────
// SESSION HELPERS
// ─────────────────────────────────────────────

const recordActivity = () => localStorage.setItem(ACTIVITY_KEY, Date.now());

const sessionExpired = () => {
  const t = parseInt(localStorage.getItem(ACTIVITY_KEY) || '0');
  return t ? (Date.now() - t) > SESSION_MS : false;
};

const clearSession = () => localStorage.removeItem(ACTIVITY_KEY);

// ─────────────────────────────────────────────
// ROUTE DETECTION
// ─────────────────────────────────────────────

const path        = window.location.pathname;
const isLogin     = path.endsWith('index.html') ||
                    path.endsWith('/')           ||
                    path.endsWith('/frontend/');
const isDashboard = path.includes('dashboard');
const params      = new URLSearchParams(window.location.search);

// ─────────────────────────────────────────────
// ROUTE GUARD
// Runs on every page load
// ─────────────────────────────────────────────

onAuthStateChanged(auth, async user => {
  if (user && user.emailVerified) {
    if (isDashboard) {
      // Check session expiry on dashboard load
      if (sessionExpired()) {
        clearSession();
        await signOut(auth);
        window.location.href = '/?reason=expired';
        return;
      }
      recordActivity();
    } else if (isLogin) {
      // Already signed in  -  skip the login page
      window.location.href = '/dashboard';
    }
  } else if (!user && isDashboard) {
    // Not authenticated  -  block dashboard
    window.location.href = '/';
  }
});

// ─────────────────────────────────────────────
// INACTIVITY MONITOR (dashboard only)
// ─────────────────────────────────────────────

if (isDashboard) {
  let throttle = null;

  ['mousedown','keydown','touchstart','scroll','click'].forEach(event => {
    document.addEventListener(event, () => {
      if (!throttle) {
        recordActivity();
        throttle = setTimeout(() => { throttle = null; }, 60_000);
      }
    }, { passive: true });
  });

  setInterval(async () => {
    if (sessionExpired()) {
      clearSession();
      if (auth.currentUser) await signOut(auth);
      window.location.href = '/?reason=expired';
    }
  }, 60_000);
}

// ─────────────────────────────────────────────
// GLOBAL LOGOUT
// ─────────────────────────────────────────────

window.logoutUser = async () => {
  clearSession();
  await signOut(auth);
  window.location.href = '/';
};

// ─────────────────────────────────────────────
// ERROR MESSAGE MAPPER
// ─────────────────────────────────────────────

function mapError(code) {
  const errors = {
    'auth/user-not-found'        : 'No account found with this email address.',
    'auth/wrong-password'        : 'Incorrect password. Please try again.',
    'auth/invalid-credential'    : 'Invalid email or password. Please try again.',
    'auth/too-many-requests'     : 'Account temporarily locked due to too many attempts.',
    'auth/network-request-failed': 'Network error. Check your connection.',
    'auth/invalid-email'         : 'Please enter a valid email address.',
    'auth/email-already-in-use'  : 'An account with this email already exists. Try signing in.',
    'auth/popup-blocked'         : 'Popup was blocked. Please allow popups for this site.',
    'auth/popup-closed-by-user'  : '',
  };
  return errors[code] || `Authentication error (${code}). Please try again.`;
}

// ─────────────────────────────────────────────
// GOOGLE PROFILE CHECK HELPER
// Used by both login and signup pages.
// Returns the Firestore profile if it exists.
// ─────────────────────────────────────────────

async function getProfile(token) {
  try {
    const res  = await fetch(`${API}/user/profile`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    const data = await res.json();
    // Profile exists and has a username = fully registered user
    return data.success && data.profile?.username ? data.profile : null;
  } catch {
    return null;
  }
}

// ═══════════════════════════════════════════════════════
// LOGIN APP  -  Alpine component for index.html
// ═══════════════════════════════════════════════════════

window.loginApp = function () {
  return {

    // ── Form state ──
    email               : '',
    password            : '',
    showPassword        : false,
    isLoading           : false,
    googleLoading       : false,
    errorMessage        : '',
    failedAttempts      : 0,

    // ── Banners ──
    verifiedBanner      : params.get('verified') === 'true',
    sessionExpiredBanner: params.get('reason')   === 'expired',

    // ── Forgot password modal ──
    showForgotModal : false,
    forgotEmail     : '',
    forgotSent      : false,
    forgotError     : '',
    forgotLoading   : false,

    // ── Google new-user profile completion modal ──
    // Only shown when a Google account has no profile yet.
    // On the LOGIN page this should NOT happen  - 
    // we block and tell them to sign up instead.
    showProfileModal : false,
    googleUser       : null,
    googleUsername   : '',
    googleCountry    : '',
    profileLoading   : false,
    profileError     : '',

    countries: [
      'United Kingdom','United States','Nigeria','Ghana','South Africa',
      'Canada','Australia','India','Germany','France','Ireland',
      'Kenya','Uganda','Tanzania','Jamaica','Trinidad and Tobago','Other'
    ],

    // ──────────────────────────────
    // LIFECYCLE
    // ──────────────────────────────

    init() {
      // Clean URL query params so they do not persist on refresh
      if (window.location.search) {
        window.history.replaceState({}, '', window.location.pathname);
      }
    },

    // ──────────────────────────────
    // EMAIL LOGIN
    // ──────────────────────────────

    async login() {
      if (this.isLoading) return;
      this.errorMessage = '';
      this.isLoading    = true;

      try {
        await setPersistence(auth, browserLocalPersistence);

        const { user } = await signInWithEmailAndPassword(
          auth,
          this.email.trim(),
          this.password
        );

        // Block unverified users
        if (!user.emailVerified) {
          await signOut(auth);
          this.errorMessage = 'Please verify your email before signing in. Check your inbox and spam/junk folder.';
          return;
        }

        recordActivity();
        window.location.href = '/dashboard';

      } catch (err) {
        this.failedAttempts++;

        if (this.failedAttempts >= 3) {
          // Auto-send reset email after 3 failures
          try {
            await fetch(`${API}/user/send-password-reset`, {
              method : 'POST',
              headers: { 'Content-Type': 'application/json' },
              body   : JSON.stringify({ email: this.email.trim() })
            });
          } catch (_) { /* silent */ }

          this.errorMessage = 'Too many failed attempts. A password reset link has been sent to your email.';
          this.failedAttempts = 0; // reset counter

        } else {
          const warning = this.failedAttempts === 2
            ? '  -  One more failure will trigger an automatic password reset.'
            : '';
          this.errorMessage = mapError(err.code) + warning;
        }

      } finally {
        this.isLoading = false;
      }
    },

    // ──────────────────────────────
    // GOOGLE LOGIN
    // Rule: ONLY works if the Google account
    // already has a registered profile.
    // New accounts must go through signup first.
    // ──────────────────────────────

    async loginWithGoogle() {
      if (this.googleLoading) return;
      this.googleLoading = true;
      this.errorMessage  = '';

      const provider = new GoogleAuthProvider();

      try {
        const result = await signInWithPopup(auth, provider);
        const user   = result.user;
        const token  = await user.getIdToken();

        // Check if this Google account has a registered profile
        const profile = await getProfile(token);

        if (profile) {
          // Registered user  -  sign in and go to dashboard
          recordActivity();
          window.location.href = '/dashboard';
        } else {
          // No profile  -  this account has not signed up yet
          // Sign them out immediately and show a clear message
          await signOut(auth);
          this.errorMessage =
            'No account found for this Google account. ' +
            'Please click "Create Account" to sign up first.';
        }

      } catch (err) {
        const msg = mapError(err.code);
        if (msg) this.errorMessage = msg;
      } finally {
        this.googleLoading = false;
      }
    },

    // ──────────────────────────────
    // FORGOT PASSWORD MODAL
    // ──────────────────────────────

    openForgot() {
      // Pre-fill with whatever email they typed
      this.forgotEmail     = this.email.trim();
      this.forgotSent      = false;
      this.forgotError     = '';
      this.showForgotModal = true;
    },

    async sendReset() {
      if (this.forgotLoading) return;
      this.forgotError   = '';
      this.forgotLoading = true;

      try {
        await fetch(`${API}/user/send-password-reset`, {
          method : 'POST',
          headers: { 'Content-Type': 'application/json' },
          body   : JSON.stringify({ email: this.forgotEmail.trim() })
        });
        // Always show success  -  prevents user enumeration
        this.forgotSent = true;
      } catch (_) {
        // Still show success on network error  -  same reason
        this.forgotSent = true;
      } finally {
        this.forgotLoading = false;
      }
    }
  };
};

// ═══════════════════════════════════════════════════════
// SIGNUP APP  -  Alpine component for signup.html
// ═══════════════════════════════════════════════════════

window.signupApp = function () {
  return {

    // ── Form fields ──
    firstName       : '',
    lastName        : '',
    username        : '',
    email           : '',
    country         : '',
    password        : '',
    confirmPassword : '',
    showPassword    : false,
    showConfirm     : false,

    // ── UI state ──
    isLoading           : false,
    googleLoading       : false,
    errorMessage        : '',
    registrationSuccess : false,

    // ── Google new-user profile completion modal ──
    showProfileModal : false,
    googleUser       : null,
    googleUsername   : '',
    googleCountry    : '',
    profileLoading   : false,
    profileError     : '',

    countries: [
      'United Kingdom','United States','Nigeria','Ghana','South Africa',
      'Canada','Australia','India','Germany','France','Ireland',
      'Kenya','Uganda','Tanzania','Jamaica','Trinidad and Tobago','Other'
    ],

    // ── Password requirements ──
    requirements: [
      { label: 'At least 8 characters',          met: false, test: p => p.length >= 8 },
      { label: 'One uppercase letter (A–Z)',      met: false, test: p => /[A-Z]/.test(p) },
      { label: 'One number (0–9)',                met: false, test: p => /[0-9]/.test(p) },
      { label: 'One special character (!@#$…)',   met: false, test: p => /[^A-Za-z0-9]/.test(p) },
    ],

    check() {
      this.requirements.forEach(r => { r.met = r.test(this.password); });
    },

    get allMet() {
      return this.requirements.every(r => r.met);
    },

    get strength() {
      return (this.requirements.filter(r => r.met).length / 4) * 100;
    },

    get strengthColor() {
      if (this.strength <= 25) return '#DC2626';
      if (this.strength <= 50) return '#D97706';
      if (this.strength <= 75) return '#D97706';
      return '#16A34A';
    },

    get strengthLabel() {
      if (!this.password)      return '';
      if (this.strength <= 25) return 'WEAK';
      if (this.strength <= 50) return 'FAIR';
      if (this.strength <= 75) return 'MODERATE';
      return 'STRONG';
    },

    get canSubmit() {
      return this.firstName.trim()      &&
             this.lastName.trim()       &&
             this.username.trim()       &&
             this.email.trim()          &&
             this.country               &&
             this.allMet                &&
             this.password === this.confirmPassword;
    },

    // ──────────────────────────────
    // EMAIL REGISTRATION
    // ──────────────────────────────

    async register() {
      this.errorMessage = '';

      if (!this.canSubmit) {
        this.errorMessage = 'Please complete all fields and meet all password requirements.';
        return;
      }

      this.isLoading = true;

      try {
        // [1] Create Firebase auth user
        const { user } = await createUserWithEmailAndPassword(
          auth,
          this.email.trim(),
          this.password
        );
        const token = await user.getIdToken();

        // [2] Save profile to Firestore via backend
        const profileRes  = await fetch(`${API}/user/profile`, {
          method : 'POST',
          headers: {
            'Content-Type' : 'application/json',
            'Authorization': `Bearer ${token}`
          },
          body: JSON.stringify({
            firstName  : this.firstName.trim(),
            lastName   : this.lastName.trim(),
            username   : this.username.trim().toLowerCase(),
            country    : this.country,
            displayName: `${this.firstName.trim()} ${this.lastName.trim()}`
          })
        });
        const profileData = await profileRes.json();

        if (!profileData.success) {
          throw new Error(profileData.error || 'Failed to save profile.');
        }

        // [3] Send verification email via SendGrid
        const emailRes  = await fetch(`${API}/user/send-verification`, {
          method : 'POST',
          headers: {
            'Content-Type' : 'application/json',
            'Authorization': `Bearer ${token}`
          },
          body: JSON.stringify({
            email    : this.email.trim(),
            firstName: this.firstName.trim()
          })
        });
        const emailData = await emailRes.json();

        if (!emailData.success) {
          console.warn('[SIGNUP] Verification email failed:', emailData.error);
          // Account was created  -  still show success but warn in console
        }

        // [4] Sign out  -  must verify email before accessing the platform
        await signOut(auth);
        this.registrationSuccess = true;

      } catch (err) {
        // Show meaningful error messages
        if (err.message.includes('taken') || err.message.includes('Username')) {
          this.errorMessage = err.message;
        } else {
          this.errorMessage = mapError(err.code) || err.message;
        }
      } finally {
        this.isLoading = false;
      }
    },

    // ──────────────────────────────
    // GOOGLE REGISTRATION
    // Rule: both new AND returning Google users
    // are handled here.
    // New → show profile modal (username + country)
    // Returning → go straight to dashboard
    // ──────────────────────────────

    async registerWithGoogle() {
      if (this.googleLoading) return;
      this.googleLoading = true;
      this.errorMessage  = '';

      const provider = new GoogleAuthProvider();

      try {
        const result = await signInWithPopup(auth, provider);
        const user   = result.user;
        const token  = await user.getIdToken();

        // Check if a profile already exists for this Google account
        const profile = await getProfile(token);

        if (profile) {
          // Already registered  -  go to dashboard
          recordActivity();
          window.location.href = '/dashboard';
        } else {
          // New Google user  -  collect username and country
          // Name and email come from their Google account
          this.googleUser = {
            uid        : user.uid,
            email      : user.email,
            displayName: user.displayName || '',
            token      : token
          };
          this.showProfileModal = true;
        }

      } catch (err) {
        const msg = mapError(err.code);
        if (msg) this.errorMessage = msg;
      } finally {
        this.googleLoading = false;
      }
    },

    // ──────────────────────────────
    // SAVE GOOGLE PROFILE
    // Called from the profile completion modal
    // ──────────────────────────────

    async saveGoogleProfile() {
      if (!this.googleUsername.trim() || !this.googleCountry) {
        this.profileError = 'Please fill in both fields to continue.';
        return;
      }

      this.profileLoading = true;
      this.profileError   = '';

      try {
        const nameParts = (this.googleUser.displayName || '').split(' ');

        const res  = await fetch(`${API}/user/profile`, {
          method : 'POST',
          headers: {
            'Content-Type' : 'application/json',
            'Authorization': `Bearer ${this.googleUser.token}`
          },
          body: JSON.stringify({
            firstName  : nameParts[0]                      || '',
            lastName   : nameParts.slice(1).join(' ')      || '',
            username   : this.googleUsername.trim().toLowerCase(),
            country    : this.googleCountry,
            displayName: this.googleUser.displayName       || this.googleUser.email
          })
        });
        const data = await res.json();

        if (!data.success) {
          this.profileError = data.error || 'Failed to save profile. Please try again.';
          return;
        }

        // Profile saved  -  go to dashboard
        recordActivity();
        window.location.href = '/dashboard';

      } catch (err) {
        this.profileError = 'Network error. Please try again.';
      } finally {
        this.profileLoading = false;
      }
    }

  };
};