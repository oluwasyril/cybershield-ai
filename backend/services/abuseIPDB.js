const axios = require('axios');

const ABUSE_BASE = 'https://api.abuseipdb.com/api/v2';

const checkIP = async (ip) => {
  try {
    const response = await axios.get(`${ABUSE_BASE}/check`, {
      headers: { 'Key': process.env.ABUSEIPDB_API_KEY, 'Accept': 'application/json' },
      params : { ipAddress: ip, maxAgeInDays: 90, verbose: false }
    });

    const d = response.data.data;

    return {
      source          : 'AbuseIPDB',
      ip              : d.ipAddress,
      abuseScore      : d.abuseConfidenceScore,
      totalReports    : d.totalReports,
      lastReportedAt  : d.lastReportedAt,
      countryCode     : d.countryCode,
      countryName     : d.countryName     || d.countryCode,
      isp             : d.isp,
      domain          : d.domain,
      usageType       : d.usageType,
      isTor           : d.isTor,
      isPublic        : d.isPublic,
      numDistinctUsers: d.numDistinctUsers || 0,
      hostnames       : d.hostnames        || []
    };
  } catch (error) {
    return {
      source : 'AbuseIPDB',
      error  : true,
      message: error.response?.data?.errors?.[0]?.detail || error.message
    };
  }
};

module.exports = { checkIP };