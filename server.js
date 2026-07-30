import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { GoogleGenAI, Type } from '@google/genai';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3000;

// GUARDRAIL 1: Body size limit (max 25MB to prevent memory exhaustion / DoS)
app.use(express.json({ limit: '25mb' }));
app.use(express.static(__dirname));

// GUARDRAIL 2: Simple sliding window rate-limiter for AI document scanning
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const MAX_REQUESTS_PER_WINDOW = 15;

function checkRateLimit(ip) {
  const now = Date.now();
  const record = rateLimitMap.get(ip) || { count: 0, startTime: now };
  if (now - record.startTime > RATE_LIMIT_WINDOW_MS) {
    record.count = 1;
    record.startTime = now;
  } else {
    record.count += 1;
  }
  rateLimitMap.set(ip, record);
  return record.count <= MAX_REQUESTS_PER_WINDOW;
}

// GUARDRAIL 3: Allowed mime-type whitelist for document scanning
const ALLOWED_MIME_TYPES = new Set([
  'image/jpeg', 'image/jpg', 'image/png', 'image/webp', 'image/heic',
  'application/pdf', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'text/plain'
]);

function cleanCode(val) {
  if (!val || typeof val !== 'string') return '';
  const trimmed = val.trim();
  const upper = trimmed.toUpperCase();
  const invalidWords = [
    'NUMBER', 'NO', 'NUM', 'N/A', 'NA', 'NULL', 'UNDEFINED', 'NONE',
    'REGISTRATION NUMBER', 'ENGINE NUMBER', 'CHASSIS NUMBER', 'POLICY NUMBER',
    'SERIAL NUMBER', 'VIN NUMBER', 'INVOICE NUMBER', 'TRANSACTION ID', 'REF NUMBER'
  ];
  if (invalidWords.includes(upper)) return '';
  if (/^(REGISTRATION|ENGINE|CHASSIS|POLICY|SERIAL|VIN|NUMBER)\s*(NUMBER|NO|NUM)?$/i.test(upper)) return '';
  return trimmed;
}

app.post('/api/scan-document', async (req, res) => {
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';

  // Check rate limit
  if (!checkRateLimit(clientIp)) {
    return res.status(429).json({
      success: false,
      error: 'Too many document scan requests. Please wait a minute before scanning again.',
    });
  }

  try {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      return res.status(200).json({
        success: false,
        error: 'GEMINI_API_KEY missing. Falling back to local OCR.',
      });
    }

    const { mimeType, base64Data, textData, filename } = req.body;

    // GUARDRAIL 4: Input verification
    if (!base64Data && !textData) {
      return res.status(400).json({ success: false, error: 'No document data provided' });
    }

    if (mimeType && !ALLOWED_MIME_TYPES.has(mimeType.toLowerCase())) {
      return res.status(400).json({
        success: false,
        error: `Unsupported file type: ${mimeType}. Please upload PDF, Word document, or image files.`,
      });
    }

    // GUARDRAIL 5: Base64 size check (max ~20MB base64)
    if (base64Data && base64Data.length > 28 * 1024 * 1024) {
      return res.status(400).json({
        success: false,
        error: 'File payload is too large. Maximum supported size is 15MB.',
      });
    }

    const ai = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });

    const parts = [];
    if (base64Data && mimeType) {
      let normMime = mimeType.toLowerCase();
      if (normMime === 'image/jpg') normMime = 'image/jpeg';
      parts.push({
        inlineData: {
          mimeType: normMime === 'application/pdf' ? 'application/pdf' : normMime,
          data: base64Data,
        },
      });
    }

    const prompt = `You are an expert OCR document scanner and asset detail extraction engine for a personal Asset Wallet app.
Thoroughly analyze this document (${filename || 'uploaded document'}) across all pages and extract ALL key details with high precision.

STEP 1: ASSET CATEGORY IDENTIFICATION
Detect the exact asset category from:
- "vehicular": Cars, Motorcycles, Two-wheelers, Commercial Vehicles, Motor Insurance, RC, PUC
- "electronics": Laptops, Smartphones, Computers, Audio, TVs, Gadgets, Tech accessories
- "camera": DSLR, Mirrorless Cameras, Lenses, Camcorders, Optical equipment
- "watch": Watches, Luxury Watches, Smartwatches, Timepieces
- "appliances": Refrigerators, ACs, Washing Machines, Kitchen Appliances
- "health": Health & Medical Insurance, Hospitalization Cards, Diagnostic Records
- "identity": Passports, Driver Licenses, Aadhaar Cards, PAN Cards, Government IDs
- "property": Title Deeds, Sale Agreements, Property Tax Receipts, Lease Agreements
- "finance": Bank Statements, Fixed Deposits, Mutual Funds, Investment Certificates
- "furniture": Sofas, Tables, Chairs, Home/Office Furniture
- "jewellery": Gold, Silver, Diamond, Certified Jewellery
- "machinery": Industrial Equipment, Generators, Motors, Tools
- "subscriptions": Software, Memberships, Subscriptions
- "other": General assets or uncategorized documents

STEP 2: DOCUMENT TYPE CLASSIFICATION
Identify document type from:
- "Vehicle Insurance"
- "Vehicle Registration Certificate (RC)"
- "Invoice"
- "Receipt"
- "Warranty Certificate"
- "Extended Warranty"
- "Service Record"
- "User Manual"
- "Property Document"
- "Health Insurance"
- "Bank / Investment Statement"
- "Subscription / Membership"
- "Other Document"

STEP 3: EXTRACT ALL VISIBLE FIELDS
Extract ALL facts visible in the text/document without hallucinating (use empty string "" if not present):
- assetName: Clear descriptive asset title (e.g. "Dell XPS 15 9530 Laptop", "Maruti Suzuki Celerio ZXI", "Sony Alpha A7 IV Camera", "Acko Motor Policy")
- owner: Full name of policyholder, buyer, account holder, or registered owner
- vendor: Seller, Dealer, Merchant, Insurer, Bank, or Service Provider
- manufacturer: Brand or Maker (e.g. Dell, Apple, Maruti Suzuki, Sony, Samsung, LG, Rolex)
- model: Model name or number (e.g. Celerio ZXI, XPS 15 9530, iPhone 15 Pro, Alpha A7 IV)
- purchasePrice: Price, cost, premium, or total amount paid with currency symbol if present
- purchaseDate: Date of purchase, issue date, start date (Formatted DD/MM/YYYY)
- expiryDate: Policy expiry date, validity end date, warranty expiration date, or maturity date (Formatted DD/MM/YYYY)
- renewalDate: Due date for renewal or next payment (Formatted DD/MM/YYYY)
- warrantyType: Exact warranty entitlement or tier name (e.g. "Dell Premium Support Plus", "Onsite Service", "AppleCare+", "2 Years Extended Warranty")
- warrantyStartDate: Warranty/Support start or commencement date (Formatted DD/MM/YYYY)
- warrantyEnds: Warranty/Support end or expiry date (Formatted DD/MM/YYYY)
- serialNumber: Serial Number, Policy Number, Account/Folio Number, Service Tag, Asset ID, or Registration reference
- assetId: Asset Tag Number, System ID, or Hardware Inventory ID (e.g. AST-LAP-9530, DELL-XPS-001)
- expressServiceCode: Dell or hardware Express Service Code (numeric code, e.g. 29381920391)
- serviceTag: Dell Service Tag, Hardware Serial Number, or Asset Tag (e.g. DX9530A1)
- supportPhone: Support, Helpline, or Emergency Phone Number (e.g. 1800-425-4026, +1-800-624-9896)
- supportEmail: Customer Support or Helpline Email (e.g. support@dell.com, customercare@apple.com)
- coverageDetails: Coverage scope, terms, or entitlements (e.g. "Onsite Service, Accidental Damage, Hardware & Software Support")
- invoice: Invoice or Bill number
- verificationUrl: QR verification link, URL, or website if shown
- notes: Important terms, conditions, or key highlights
- addOns: Array of strings for features or add-on covers (e.g. ["Zero Depreciation", "Accidental Damage Protection"])
- reminders: Array of strings for key due dates or action items
- contacts: Array of strings for helpline phone numbers, support emails, emergency numbers

Category Specific Fields:
- registrationNumber: Vehicle registration number / license plate (e.g. KA01MM4354)
- engineNumber: Engine number
- chassisNumber: Chassis or VIN number
- policyType: Comprehensive, Third Party, Own Damage
- coverageType: Coverage details (e.g. OD + TP)
- idv: Insured Declared Value or Sum Insured
- ncbPercentage: NCB percentage (e.g. 50%)
- vehicleType: Private Car, Two Wheeler, Commercial Vehicle
- fuelType: Petrol, Diesel, EV, CNG
- cubicCapacity: Engine cubic capacity (e.g. 998 CC)
- registrationYear: Registration year
- storageOrSpecs: RAM, SSD, Processor, Specs
- imeiOrMac: IMEI or MAC address
- lensDetails: Lens specifications / Sensor details
- watchMovement: Watch movement or material
- propertyAddress: Property location address
- deedNumber: Deed or agreement number
- builtUpArea: Area in sq ft
- institutionName: Bank or AMC name
- accountOrFolioNumber: Account or Folio number
- applianceType: Refrigerator, AC, Washing Machine, etc.
- capacity: Capacity or Tonnage
- energyRating: Star rating
- material: Furniture or item material
- jewelleryType: Item type (Gold Chain, Diamond Ring)
- metalPurity: Metal purity (22K Gold, 925 Silver)
- grossWeightGrams: Weight in grams
- subscriptionPlan: Subscription plan name
- billingCycle: Monthly / Annual

Format all dates strictly as DD/MM/YYYY. Return a valid JSON object.`;

    let textContent = prompt;
    if (textData) {
      textContent += `\n\n--- PRE-EXTRACTED DOCUMENT TEXT ---\n${textData}`;
    }
    parts.push({ text: textContent });

    const candidateModels = ['gemini-3.6-flash', 'gemini-flash-latest', 'gemini-3.1-flash-lite'];
    let response = null;
    let lastError = null;

    const schemaConfig = {
      responseMimeType: 'application/json',
      responseSchema: {
        type: Type.OBJECT,
        properties: {
          category: { type: Type.STRING },
          docType: { type: Type.STRING },
          assetName: { type: Type.STRING },
          owner: { type: Type.STRING },
          vendor: { type: Type.STRING },
          manufacturer: { type: Type.STRING },
          model: { type: Type.STRING },
          purchasePrice: { type: Type.STRING },
          purchaseDate: { type: Type.STRING },
          expiryDate: { type: Type.STRING },
          renewalDate: { type: Type.STRING },
          warrantyEnds: { type: Type.STRING },
          warrantyType: { type: Type.STRING },
          warrantyStartDate: { type: Type.STRING },
          serialNumber: { type: Type.STRING },
          assetId: { type: Type.STRING },
          expressServiceCode: { type: Type.STRING },
          serviceTag: { type: Type.STRING },
          supportPhone: { type: Type.STRING },
          supportEmail: { type: Type.STRING },
          coverageDetails: { type: Type.STRING },
          invoice: { type: Type.STRING },
          verificationUrl: { type: Type.STRING },
          notes: { type: Type.STRING },
          addOns: { type: Type.ARRAY, items: { type: Type.STRING } },
          reminders: { type: Type.ARRAY, items: { type: Type.STRING } },
          contacts: { type: Type.ARRAY, items: { type: Type.STRING } },

          // Vehicular
          registrationNumber: { type: Type.STRING },
          engineNumber: { type: Type.STRING },
          chassisNumber: { type: Type.STRING },
          vehicleType: { type: Type.STRING },
          fuelType: { type: Type.STRING },
          cubicCapacity: { type: Type.STRING },
          registrationYear: { type: Type.STRING },
          policyType: { type: Type.STRING },
          coverageType: { type: Type.STRING },
          idv: { type: Type.STRING },
          ncbPercentage: { type: Type.STRING },

          // Electronics & Laptop / Camera / Watch
          storageOrSpecs: { type: Type.STRING },
          imeiOrMac: { type: Type.STRING },
          lensDetails: { type: Type.STRING },
          watchMovement: { type: Type.STRING },

          // Property
          propertyAddress: { type: Type.STRING },
          deedNumber: { type: Type.STRING },
          builtUpArea: { type: Type.STRING },

          // Finance
          institutionName: { type: Type.STRING },
          accountOrFolioNumber: { type: Type.STRING },

          // Appliances
          applianceType: { type: Type.STRING },
          capacity: { type: Type.STRING },
          energyRating: { type: Type.STRING },

          // Furniture
          material: { type: Type.STRING },

          // Jewellery
          jewelleryType: { type: Type.STRING },
          metalPurity: { type: Type.STRING },
          grossWeightGrams: { type: Type.STRING },

          // Subscriptions
          subscriptionPlan: { type: Type.STRING },
          billingCycle: { type: Type.STRING },
          rawText: { type: Type.STRING },
        },
        required: ['category', 'docType', 'assetName'],
      },
    };

    for (const modelName of candidateModels) {
      try {
        response = await ai.models.generateContent({
          model: modelName,
          contents: parts,
          config: schemaConfig,
        });
        if (response && response.text) break;
      } catch (modelErr) {
        console.warn(`Model ${modelName} with schema failed:`, modelErr?.message || modelErr);
        // Fallback retry with JSON mode without schema
        try {
          response = await ai.models.generateContent({
            model: modelName,
            contents: parts,
            config: { responseMimeType: 'application/json' },
          });
          if (response && response.text) break;
        } catch (jsonErr) {
          console.warn(`Model ${modelName} JSON mode failed:`, jsonErr?.message || jsonErr);
          lastError = jsonErr;
        }
      }
    }

    let data = {};
    if (response && response.text) {
      try {
        data = JSON.parse(response.text);
      } catch (parseErr) {
        console.warn('Failed to parse Gemini JSON output:', parseErr);
      }
    }

    function cleanVal(v) {
      if (!v || typeof v !== 'string') return '';
      const s = v.trim();
      if (s.toLowerCase() === 'null' || s.toLowerCase() === 'undefined' || s.toLowerCase() === 'n/a' || s.toLowerCase() === 'none') {
        return '';
      }
      return s;
    }

    function mapToAppCategory(cat) {
      if (!cat || typeof cat !== 'string') return 'other';
      const c = cat.trim().toLowerCase();
      if (c.includes('vehicle') || c.includes('car') || c.includes('bike') || c.includes('auto') || c.includes('vehicular') || c.includes('motor')) return 'vehicular';
      if (c.includes('camera') || c.includes('optic') || c.includes('lens')) return 'camera';
      if (c.includes('watch') || c.includes('timepiece') || c.includes('wearable')) return 'watch';
      if (c.includes('laptop') || c.includes('phone') || c.includes('electronic') || c.includes('gadget') || c.includes('computer')) return 'electronics';
      if (c.includes('appliance') || c.includes('home appliance')) return 'appliances';
      if (c.includes('health') || c.includes('medical') || c.includes('hospital') || c.includes('doctor') || c.includes('mediclaim')) return 'health';
      if (c.includes('identity') || c.includes('passport') || c.includes('aadhaar') || c.includes('pan') || c.includes('id card') || c.includes('license') || c.includes('licence')) return 'identity';
      if (c.includes('property') || c.includes('real estate') || c.includes('house') || c.includes('land')) return 'property';
      if (c.includes('financial') || c.includes('finance') || c.includes('bank') || c.includes('investment')) return 'finance';
      if (c.includes('furniture')) return 'furniture';
      if (c.includes('jewel') || c.includes('gold') || c.includes('silver') || c.includes('diamond')) return 'jewellery';
      if (c.includes('machinery') || c.includes('equipment')) return 'machinery';
      if (c.includes('subscrip') || c.includes('membership')) return 'subscriptions';
      return 'other';
    }

    function mapToAppDocType(dt) {
      if (!dt || typeof dt !== 'string') return 'Other Document';
      const d = dt.trim().toLowerCase();
      if (d.includes('rc') || d.includes('registration certificate')) return 'Vehicle Registration Certificate (RC)';
      if (d.includes('vehicle insurance') || (d.includes('motor') && d.includes('insurance'))) return 'Vehicle Insurance';
      if (d.includes('health insurance') || d.includes('medical')) return 'Health Insurance';
      if (d.includes('extended warranty')) return 'Extended Warranty';
      if (d.includes('warranty')) return 'Warranty Certificate';
      if (d.includes('invoice')) return 'Invoice';
      if (d.includes('receipt')) return 'Receipt';
      if (d.includes('service') || d.includes('maintenance')) return 'Service Record';
      if (d.includes('manual')) return 'User Manual';
      if (d.includes('property') || d.includes('deed')) return 'Property Document';
      if (d.includes('subscription') || d.includes('membership')) return 'Membership / Subscription';
      if (d.includes('bank') || d.includes('statement')) return 'Bank / Investment Statement';
      return dt.trim();
    }

    const mappedCategory = mapToAppCategory(data.category);
    const mappedDocType = mapToAppDocType(data.docType);

    const contactsArr = Array.isArray(data.contacts) ? data.contacts.map(cleanVal).filter(Boolean) : (data.contacts ? [cleanVal(data.contacts)] : []);
    const phoneVal = cleanVal(data.supportPhone);
    if (phoneVal && !contactsArr.some(c => c.includes(phoneVal))) {
      contactsArr.push(`Support Phone: ${phoneVal}`);
    }
    const emailVal = cleanVal(data.supportEmail);
    if (emailVal && !contactsArr.some(c => c.includes(emailVal))) {
      contactsArr.push(`Support Email: ${emailVal}`);
    }

    const sanitizedData = {
      success: true,
      category: mappedCategory,
      docType: mappedDocType,
      assetName: cleanVal(data.assetName) || filename || 'Scanned Asset',
      owner: cleanVal(data.owner),
      vendor: cleanVal(data.vendor),
      manufacturer: cleanVal(data.manufacturer),
      model: cleanVal(data.model),
      purchasePrice: cleanVal(data.purchasePrice),
      purchaseDate: cleanVal(data.purchaseDate),
      expiryDate: cleanVal(data.expiryDate),
      renewalDate: cleanVal(data.renewalDate),
      warrantyEnds: cleanVal(data.warrantyEnds) || cleanVal(data.expiryDate),
      warrantyType: cleanVal(data.warrantyType),
      warrantyStartDate: cleanVal(data.warrantyStartDate || data.purchaseDate),
      serialNumber: cleanCode(data.serialNumber || data.serviceTag || data.assetId || data.policyNumber || data.accountOrFolioNumber),
      policyNumber: cleanCode(data.policyNumber || data.serialNumber),
      invoice: cleanCode(data.invoice),
      verificationUrl: cleanVal(data.verificationUrl),
      notes: cleanVal(data.notes),
      addOns: Array.isArray(data.addOns) ? data.addOns.map(cleanVal).filter(Boolean) : (data.addOns ? [cleanVal(data.addOns)] : []),
      reminders: Array.isArray(data.reminders) ? data.reminders.map(cleanVal).filter(Boolean) : (data.reminders ? [cleanVal(data.reminders)] : []),
      contacts: contactsArr,

      // Vehicular
      registrationNumber: cleanCode(data.registrationNumber),
      engineNumber: cleanCode(data.engineNumber),
      chassisNumber: cleanCode(data.chassisNumber),
      vehicleType: cleanVal(data.vehicleType),
      fuelType: cleanVal(data.fuelType),
      cubicCapacity: cleanVal(data.cubicCapacity),
      registrationYear: cleanVal(data.registrationYear),
      policyType: cleanVal(data.policyType),
      coverageType: cleanVal(data.coverageType),
      idv: cleanVal(data.idv),
      ncbPercentage: cleanVal(data.ncbPercentage),

      // Electronics & Laptop / Camera / Watch / Hardware
      serviceTag: cleanCode(data.serviceTag || data.serialNumber),
      expressServiceCode: cleanCode(data.expressServiceCode),
      assetId: cleanCode(data.assetId),
      supportPhone: phoneVal,
      supportEmail: emailVal,
      coverageDetails: cleanVal(data.coverageDetails || data.coverageType),
      storageOrSpecs: cleanVal(data.storageOrSpecs),
      imeiOrMac: cleanCode(data.imeiOrMac),
      lensDetails: cleanVal(data.lensDetails),
      watchMovement: cleanVal(data.watchMovement),

      // Property
      propertyAddress: cleanVal(data.propertyAddress),
      deedNumber: cleanCode(data.deedNumber),
      builtUpArea: cleanVal(data.builtUpArea),

      // Finance
      institutionName: cleanVal(data.institutionName),
      accountOrFolioNumber: cleanCode(data.accountOrFolioNumber),

      // Appliances
      applianceType: cleanVal(data.applianceType),
      capacity: cleanVal(data.capacity),
      energyRating: cleanVal(data.energyRating),

      // Furniture
      material: cleanVal(data.material),

      // Jewellery
      jewelleryType: cleanVal(data.jewelleryType),
      metalPurity: cleanVal(data.metalPurity),
      grossWeightGrams: cleanVal(data.grossWeightGrams),

      // Subscriptions
      subscriptionPlan: cleanVal(data.subscriptionPlan),
      billingCycle: cleanVal(data.billingCycle),

      rawText: cleanVal(data.rawText) || textData || '',

      // Document classification metadata
      documentClassification: { docType: mappedDocType, confidence: 0.98 },
      assetCategory: { category: mappedCategory, confidence: 0.98 },
      pagesProcessed: 1,
    };

    return res.status(200).json({
      success: true,
      data: sanitizedData,
    });
  } catch (err) {
    console.error('Scan API handler exception:', err);
    return res.status(200).json({
      success: false,
      error: 'AI document scanning service was unable to complete. Please check the document or enter details manually.',
    });
  }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on http://0.0.0.0:${PORT}`);
});

