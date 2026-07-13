const admin = require('firebase-admin');

if (!admin.apps.length) {

  // [1] On Render, we read the service account from an env variable
  //     Locally, we still use the JSON file
  let serviceAccount;

  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    // Production — parse the JSON string from environment
    serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
  } else {
    // Local development — read from file
    serviceAccount = require('../serviceAccountKey.json');
  }

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}

const db   = admin.firestore();
const auth = admin.auth();

module.exports = { admin, db, auth };