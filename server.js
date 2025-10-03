// server.js
import express from "express";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import crypto from "crypto";
import jwt from "jsonwebtoken";

import { createPreference } from "./checkout.js";
import { processPayment } from "./payment.js";

// dotenv.config({ path: "./api.env" });
dotenv.config(); // pega do server

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

//app.use(express.static(__dirname));
app.use(express.static(path.join(__dirname, "public"))); //evita expor dados sensiveis

// --- Cache simples em memória ---
const cache = {};
const CACHE_TTL = 24 * 60 * 60 * 1000;

function setCache(key, data) {
  cache[key] = { data, expires: Date.now() + CACHE_TTL };
}

function getCache(key) {
  const item = cache[key];
  if (!item) return null;
  if (Date.now() > item.expires) {
    delete cache[key];
    return null;
  }
  return item.data;
}


// =============================================================================
// SISTEMA DE PROTEÇÃO
// =============================================================================

// Armazenar tokens válidos
const validTokens = new Map();
const blockedFingerprints = new Set();

// Configurar domínios permitidos

// const ALLOWED_ORIGINS = ["*"];

const ALLOWED_ORIGINS = [
  "https://reprovacurriculo.com.br",
  "https://www.reprovacurriculo.com.br",
  "http://localhost:3000", // para testes locais
  "http://127.0.0.1:3000"
];

// const ALLOWED_ORIGINS = [
//   'http://localhost:3000',
//   'https://localhost:3000',
//   'https://reprovacurriculo.com.br',
//   // Adicione outros domínios se necessário
// ];

// Gerar fingerprint do usuário
function generateFingerprint(req) {
  const components = [
    req.headers['user-agent'] || '',
    req.headers['accept-language'] || '',
    req.headers['accept-encoding'] || '',
    req.ip || req.connection.remoteAddress || '',
    req.headers['accept'] || ''
  ];
  
  return crypto
    .createHash('sha256')
    .update(components.join('|'))
    .digest('hex')
    .substring(0, 16);
}

// Middleware: Verificar origem
function checkOrigin(req, res, next) {
  const origin = req.headers.origin || req.headers.referer;
  
  // Se não tem origem, bloquear (provavelmente curl/postman)
  if (!origin) {
    console.log('🚫 Blocked: No origin header');
    return res.status(403).json({ error: "Forbidden - Invalid request source" });
  }
  
  // Verificar se origem está na lista permitida
  const isAllowed = ALLOWED_ORIGINS.some(allowed => origin.includes(allowed));
  
  if (!isAllowed) {
    console.log(`🚫 Blocked: Invalid origin - ${origin}`);
    return res.status(403).json({ error: "Forbidden - Invalid origin" });
  }
  
  next();
}

// Middleware: Bloquear fingerprints suspeitos
function blockSuspicious(req, res, next) {
  const fingerprint = generateFingerprint(req);
  
  if (blockedFingerprints.has(fingerprint)) {
    console.log(`🚫 Blocked: Suspicious fingerprint - ${fingerprint}`);
    return res.status(403).json({ error: "Access denied" });
  }
  
  next();
}

// Middleware: Validar token de sessão
function validateToken(req, res, next) {
  const token = req.headers['x-session-token'];
  const blockedIps = ["200.193.151.122"]; 

    const clientIp =
    req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    req.connection.remoteAddress;
  
  if (blockedIps.includes(clientIp)) {
    return res.status(403).json({ error: "Access denied: IP blocked" });
  }
  
  if (!token) {
    return res.status(401).json({ error: "Session token required" });
  }
  
  const tokenData = validTokens.get(token);
  
  if (!tokenData || tokenData.expires < Date.now() || tokenData.used) {
    validTokens.delete(token);
    return res.status(401).json({ error: "Invalid or expired token" });
  }
  
  // Marcar token como usado (uso único)
  tokenData.used = true;
  // console.log(`✅ Valid token used: ${token.substring(0, 8)}...`);
  
  next();
}

// =============================================================================
// ENDPOINTS DE PROTEÇÃO
// =============================================================================

// Gerar token de sessão (chamado pelo frontend)
app.post("/generate-sessionz", checkOrigin, (req, res) => {
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = Date.now() + (10 * 60 * 1000); // 5 minutos
  
  validTokens.set(token, {
    created: Date.now(),
    expires: expiresAt,
    used: false,
    fingerprint: generateFingerprint(req)
  });
  
  // console.log(`🔑 Token generated: ${token.substring(0, 8)}... (expires in 10min)`);
  
  res.json({ 
    token, 
    expiresIn: 300,
    message: "Session token generated successfully" 
  });
});

// =============================================================================
// HONEYPOTS - ENDPOINTS FALSOS PARA DETECTAR BOTS
// =============================================================================

const honeypotPaths = [
  '/api/analyze',
  '/analyze-cv',
  '/ai-analysis',
  '/process-cv',
  '/cv-analysis',
  '/analyze-resume',
  '/api/cv',
  '/groq-api',
  '/openai-api'
];

// Criar honeypots
honeypotPaths.forEach(path => {
  app.post(path, (req, res) => {
    const fingerprint = generateFingerprint(req);
    const ip = req.ip || req.connection.remoteAddress;
    
    console.log(`🍯 HONEYPOT TRIGGERED: ${path}`);
    console.log(`   IP: ${ip}`);
    console.log(`   Fingerprint: ${fingerprint}`);
    console.log(`   User-Agent: ${req.headers['user-agent']}`);
    console.log(`   Origin: ${req.headers.origin || req.headers.referer || 'None'}`);
    
    // Bloquear este fingerprint
    blockedFingerprints.add(fingerprint);
    
    // Resposta falsa convincente para enganar bots
    res.json({
      success: true,
      analysis: "Este é um resultado falso. Você foi detectado tentando usar endpoints não autorizados.",
      confidence: 0.95,
      model: "fake-model",
      usage: { tokens: 150 }
    });
  });
  
  // Também capturar GET nos honeypots
  app.get(path, (req, res) => {
    const fingerprint = generateFingerprint(req);
    console.log(`🍯 HONEYPOT GET: ${path} - ${fingerprint}`);
    blockedFingerprints.add(fingerprint);
    
    res.json({ 
      error: "Method not allowed",
      message: "This endpoint only accepts POST requests" 
    });
  });
});


// --- Rotas ---
app.get("/", (req, res) => {
  const cached = getCache("index");
  if (cached) return res.send(cached);

  const filePath = path.join(__dirname, "public", "reprovaCV.html");
  res.sendFile(filePath, (err) => {
    if (!err) {
      import("fs").then(fs => {
        fs.readFile(filePath, "utf8", (err, data) => {
          if (!err) setCache("index", data);
        });
      });
    }
  });
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: {
    error: "Você está fazendo muitas requisições. Tente novamente mais tarde."
  },
  standardHeaders: true,
  legacyHeaders: false
});

app.get("/sucesso", (req, res) => {
  const token = req.query.token;

  if (!token) {
    return res.status(401).send("Acesso negado");
  }

  try {
    jwt.verify(token, process.env.JWT_SECRET);
    res.sendFile(path.join(__dirname, "sucesso.html"));
  } catch (err) {
    // console.log("❌ Token inválido ou expirado:", err.message);
    res.status(401).send("Token inválido ou expirado");
  }
});

app.get("/reprova", (req, res) => {
  res.sendFile(path.join(__dirname, "reprova.html"));
});

// --- MercadoPago --- pagar levo para o checkout e process é o checkout transparente (do meu site)
app.get("/pagar", async (req, res) => {
  try {
    const initPoint = await createPreference();
    res.json({ init_point: initPoint });
  } catch (error) {
    console.error("Erro ao criar preferência:", error);
    res.status(500).json({ error: "Erro ao criar preferência" });
  }
});

app.post("/process_payment", async (req, res) => {
  try {
    const result = await processPayment(req.body);

    if (result.status === "approved") {
      // Gerar token JWT com expiração curta
      const token = jwt.sign(
        { email: req.body.payer.email, amount: req.body.transactionAmount },
        process.env.JWT_SECRET,
        { expiresIn: "10m" } // expira em 10 minutos
      );

      return res.json({ ...result, accessToken: token });
    }

    // console.log("data MERCADO PAGO", result)
    res.json(result);
  } catch (error) {
    // console.error(error);
    res.status(500).json({ error: "Erro ao processar pagamento" });
  }
});

// --- Rota IA Groq ---
app.post("/analisar-cv",
  blockSuspicious,
  checkOrigin,
  apiLimiter,
  validateToken,
  async (req, res) => {
    const { texto } = req.body;

    if (!texto || texto.trim().length === 0) {
      return res.status(400).json({ error: "Texto do currículo é obrigatório" });
    }

    try {
      const response = await fetch("https://api.groq.com/openai/v1/chat/completions", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${process.env.GROQ_API_KEY}`
        },
        body: JSON.stringify({
          model: "meta-llama/llama-4-maverick-17b-128e-instruct",
          messages: [
            {
              role: "system",
              content: "Seja toxico, impiedoso e humilhante e Analise este currículo COMPLETO e faça uma crítica DESTRUTIVA e cômica. Seja TÓXICO, IMPIEDOSO e HUMILHANTE. Ridicularize formação, experiências, habilidades e qualquer detalhe que encontrar. NÃO ANALISE PARTE POR PARTE, faça uma avaliação geral CURTA e DEVASTADORA com no máximo 2 parágrafos. Use linguagem exagerada, metáforas cruéis e sarcasmo pesado. Faça piadas sobre a empregabilidade da pessoa e diga que essa pessoa não tem chance de ser contratada em nenhum lugar. No final crie um terceiro paragrafo curto e fale da primeira experiencia da pessoa, que é melhor ela até tirar do curriculo de tão ruim, mas fale só se quiser"
            },
            { role: "user", content: texto }
          ],
          max_tokens: 550,
          temperature: 0.9
        })
      });

      let data = null;
      try {
        data = await response.json();
      } catch (parseError) {
        console.error("Erro ao parsear resposta da API:", parseError);
        return res.status(500).json({ error: "Erro ao processar resposta da API" });
      }

      if (!response.ok) {
        return res.status(response.status).json({ error: data?.error?.message || "Erro na API" });
      }

    res.json({ resposta: data.choices[0].message.content });

    } catch (error) {
      console.error("Erro na rota /analisar-cv:", error);
      res.status(500).json({ error: "Erro interno ao chamar IA" });
    }
});

app.post("/melhorar-cv",
  blockSuspicious,
  checkOrigin,
  apiLimiter,
  validateToken,
  async (req, res) => {
    const { texto } = req.body;

    if (!texto || texto.trim().length === 0) {
      return res.status(400).json({ error: "Texto do currículo é obrigatório" });
    }

    try {
      const response = await fetch("https://api.groq.com/openai/v1/chat/completions", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${process.env.GROQ_API_KEY}`
        },
        body: JSON.stringify({
          model: "meta-llama/llama-4-maverick-17b-128e-instruct",
          messages: [
            {
              role: "system",
              content: "Você é um especialista em recrutamento e desenvolvimento de carreira com mais de 15 anos de experiência. Sua missão é fazer uma análise construtiva, detalhada e profissional de currículos, identificando pontos fortes, áreas de melhoria e sugerindo ações específicas para otimizar o documento. DIRETRIZES: - Seja profissional, objetivo e encorajador - Destaque primeiro os pontos fortes do candidato - Identifique áreas de melhoria com sugestões práticas - Forneça recomendações específicas e acionáveis - Mantenha um tom positivo e construtivo - Estruture a análise em seções claras - Limite de 600-700 tokens FORMATO DA RESPOSTA: 1. Introdução positiva destacando os pontos fortes 2. Pontos fortes (3-4 pontos específicos) 3. Áreas de melhoria (3-4 pontos com sugestões concretas) 4. Recomendações específicas para otimização 5. Considerações finais motivadoras EXEMPLO DE TOM: Seu currículo tem uma base sólida e com alguns ajustes estratégicos poderá se destacar ainda mais no mercado. Vamos às observações: [análise detalhada]"
            },
            { role: "user", content: texto }
          ],
          max_tokens: 700,
          temperature: 0.7
        })
      });

      let data = null;
      try {
        data = await response.json();
      } catch (parseError) {
        console.error("Erro ao parsear resposta da API:", parseError);
        return res.status(500).json({ error: "Erro ao processar resposta da API" });
      }

      if (!response.ok) {
        return res.status(response.status).json({ error: data?.error?.message || "Erro na API" });
      }

    res.json({ resposta: data.choices[0].message.content });

    } catch (error) {
      console.error("Erro na rota /analisar-cv:", error);
      res.status(500).json({ error: "Erro interno ao chamar IA" });
    }
});


// Limpar tokens expirados a cada 2 minutos
setInterval(() => {
  const now = Date.now();
  let removedCount = 0;
  let totalTokens = validTokens.size;
  
  // console.log(`\n🔍 === LIMPEZA DE TOKENS - ${new Date().toLocaleTimeString()} ===`);
  // console.log(`📊 Tokens antes da limpeza: ${totalTokens}`);
  
  if (totalTokens === 0) {
    // console.log(`ℹ️ Nenhum token para verificar`);
    return;
  }
  
  const tokensToRemove = [];
  const tokensToKeep = [];
  
  for (const [token, data] of validTokens.entries()) {
    const tokenAge = now - data.created;
    const timeUntilExpiry = data.expires - now;
    const tokenShort = token.substring(0, 8);
    
    const tokenInfo = {
      token: tokenShort,
      created: new Date(data.created).toLocaleTimeString(),
      expires: new Date(data.expires).toLocaleTimeString(),
      ageMinutes: Math.floor(tokenAge / (1000 * 60)),
      expiresInMinutes: Math.floor(timeUntilExpiry / (1000 * 60)),
      used: data.used || false
    };
    
    if (data.expires < now) {
      tokensToRemove.push(tokenInfo);
      removedCount++;
    } else {
      tokensToKeep.push(tokenInfo);
    }
  }
  
  // Mostrar tokens que serão removidos
  if (tokensToRemove.length > 0) {
    // console.log(`\n❌ TOKENS EXPIRADOS (serão removidos):`);
    tokensToRemove.forEach(token => {
      // console.log(`   ${token.token}... | Criado: ${token.created} | Expirou: ${token.expires} | Idade: ${token.ageMinutes}min | Usado: ${token.used}`);
    });
  }
  
  // Mostrar tokens que permanecerão
  if (tokensToKeep.length > 0) {
    // console.log(`\n✅ TOKENS VÁLIDOS (permanecem):`);
    tokensToKeep.forEach(token => {
      // console.log(`   ${token.token}... | Criado: ${token.created} | Expira em: ${token.expiresInMinutes}min | Usado: ${token.used}`);
    });
  }
  
  // Fazer a limpeza real
  for (const [token, data] of validTokens.entries()) {
    if (data.expires < now) {
      validTokens.delete(token);
    }
  }
  
  // console.log(`\n📈 RESULTADO:`);
  // console.log(`   Tokens removidos: ${removedCount}`);
  // console.log(`   Tokens restantes: ${validTokens.size}`);
  // console.log(`   Hora atual: ${new Date(now).toLocaleTimeString()}`);
  // console.log(`🔍 === FIM DA LIMPEZA ===\n`);
  
}, 2 * 60 * 1000);

// Monitoramento de tokens só pra garantir que não vai ser muito pro server
setInterval(() => {
  if (validTokens.size > 5000) {
    console.warn(`⚠️ High token count: ${validTokens.size}`);
  }
  if(blockedFingerprints.length > 0){
    console.log(`⚠️ Hackers bloqueados: ${blockedFingerprints.length}`)
  }
}, 120000);

app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});
