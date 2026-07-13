const axios = require('axios');

const GSB_URL = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';

const checkUrl = async (url) => {
  try {
    const payload = {
      client: { clientId: 'cybershield-ai', clientVersion: '2.0.0' },
      threatInfo: {
        threatTypes     : ['MALWARE','SOCIAL_ENGINEERING','UNWANTED_SOFTWARE','POTENTIALLY_HARMFUL_APPLICATION'],
        platformTypes   : ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries   : [{ url }]
      }
    };

    const response = await axios.post(
      `${GSB_URL}?key=${process.env.GOOGLE_SAFE_BROWSING_API_KEY}`,
      payload
    );

    const matches = response.data.matches || [];

    return {
      source     : 'GoogleSafeBrowsing',
      url,
      isFlagged  : matches.length > 0,
      threatCount: matches.length,
      threats    : matches.map(m => ({ type: m.threatType, platform: m.platformType }))
    };
  } catch (error) {
    return {
      source : 'GoogleSafeBrowsing',
      error  : true,
      message: error.response?.data?.error?.message || error.message
    };
  }
};

module.exports = { checkUrl };