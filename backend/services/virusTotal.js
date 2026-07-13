const axios = require('axios');

const VT_BASE = 'https://www.virustotal.com/api/v3';

const scanUrl = async (url) => {
  const encoded = Buffer.from(url)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

  try {
    await axios.post(
      `${VT_BASE}/urls`,
      `url=${encodeURIComponent(url)}`,
      {
        headers: {
          'x-apikey'    : process.env.VIRUSTOTAL_API_KEY,
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );

    const report = await axios.get(`${VT_BASE}/urls/${encoded}`, {
      headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY }
    });

    const attrs = report.data.data.attributes;
    const stats = attrs.last_analysis_stats;

    return {
      source            : 'VirusTotal',
      url,
      malicious         : stats.malicious,
      suspicious        : stats.suspicious,
      harmless          : stats.harmless,
      undetected        : stats.undetected,
      timeout           : stats.timeout,
      reputation        : attrs.reputation       || 0,
      timesSubmitted    : attrs.times_submitted  || 0,
      lastAnalysisDate  : attrs.last_analysis_date
        ? new Date(attrs.last_analysis_date * 1000).toISOString()
        : null,
      categories        : attrs.categories       || {},
      totalEngines      : (stats.malicious + stats.suspicious + stats.harmless + stats.undetected),
      detectionRatio    : `${stats.malicious}/${stats.malicious + stats.suspicious + stats.harmless + stats.undetected}`
    };
  } catch (error) {
    return {
      source : 'VirusTotal',
      error  : true,
      message: error.response?.data?.error?.message || error.message
    };
  }
};

module.exports = { scanUrl };