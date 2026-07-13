import { initializeApp }  from 'https://www.gstatic.com/firebasejs/10.12.0/firebase-app.js';
import { getAuth }        from 'https://www.gstatic.com/firebasejs/10.12.0/firebase-auth.js';
import { getFirestore }   from 'https://www.gstatic.com/firebasejs/10.12.0/firebase-firestore.js';

// [!] Replace with YOUR Firebase project config
const firebaseConfig = {
  apiKey: "AIzaSyCwz8yUn3fFLBXXui7EDaxvtHahwJTJTAY",
  authDomain: "cyber-threat-platform-12e4b.firebaseapp.com",
  projectId: "cyber-threat-platform-12e4b",
  storageBucket: "cyber-threat-platform-12e4b.firebasestorage.app",
  messagingSenderId: "405030971292",
  appId: "1:405030971292:web:24553a3c0a5db09bac4a59"
};

const app = initializeApp(firebaseConfig);

export const auth = getAuth(app);
export const db   = getFirestore(app);