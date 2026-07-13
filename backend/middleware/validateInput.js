const isValidUrl = (string) => {
  try {
    const url = new URL(string);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch { return false; }
};

const isValidIP = (ip) => {
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6  = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
  if (!ipv4.test(ip) && !ipv6.test(ip)) return false;
  if (ipv4.test(ip)) {
    return ip.split('.').every(o => parseInt(o) >= 0 && parseInt(o) <= 255);
  }
  return true;
};

const validateScanInput = (req, res, next) => {
  if (!req.body || typeof req.body !== 'object') {
    return res.status(400).json({ success: false, error: 'Request body missing.' });
  }
  const { url } = req.body;
  if (!url || typeof url !== 'string') {
    return res.status(400).json({ success: false, error: 'A URL string is required.' });
  }
  const clean = url.trim();
  if (!isValidUrl(clean)) {
    return res.status(400).json({ success: false, error: 'Invalid URL. Must begin with http:// or https://' });
  }
  req.body.url = clean;
  next();
};

const validateIPInput = (req, res, next) => {
  if (!req.body || typeof req.body !== 'object') {
    return res.status(400).json({ success: false, error: 'Request body missing.' });
  }
  const { ip } = req.body;
  if (!ip || typeof ip !== 'string') {
    return res.status(400).json({ success: false, error: 'An IP address string is required.' });
  }
  const clean = ip.trim();
  if (!isValidIP(clean)) {
    return res.status(400).json({ success: false, error: 'Invalid IP address format.' });
  }
  req.body.ip = clean;
  next();
};

module.exports = { validateScanInput, validateIPInput };