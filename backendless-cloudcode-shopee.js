/**
 * ══════════════════════════════════════════════════════════════════
 *  BACKENDLESS CLOUD CODE — Serviço Shopee
 *  Arquivo: services/shopee/index.js
 *
 *  INSTRUÇÕES DE DEPLOY:
 *  1. No painel Backendless > Business Logic > Services
 *  2. Crie um serviço chamado "shopee"
 *  3. Cole este código (ou cada método separado)
 *  4. Configure as variáveis de ambiente (App Settings):
 *     - SHOPEE_PARTNER_ID   → seu Partner ID
 *     - SHOPEE_PARTNER_KEY  → seu Partner Key (SECRET — nunca exposto ao front!)
 *     - SHOPEE_REDIRECT_URL → URL de callback OAuth (pode ser sua GitHub Pages + /shopee-callback.html)
 *     - SHOPEE_ENV          → "live" ou "test"
 *
 *  SEGURANÇA:
 *  - O front-end (GitHub Pages) NUNCA vê a Partner Key.
 *  - O front-end chama apenas: POST /services/shopee/<método>
 *  - Tokens OAuth ficam na tabela ShopeeConfig do Backendless (não no browser)
 * ══════════════════════════════════════════════════════════════════
 */

'use strict';

const Backendless = require('backendless');
const crypto = require('crypto');

// ── Configurações (via App Environment Variables) ──────────────────
const PARTNER_ID    = Backendless.ServerCode.getEnv('SHOPEE_PARTNER_ID');
const PARTNER_KEY   = Backendless.ServerCode.getEnv('SHOPEE_PARTNER_KEY');
const REDIRECT_URL  = Backendless.ServerCode.getEnv('SHOPEE_REDIRECT_URL');
const SHOPEE_ENV    = Backendless.ServerCode.getEnv('SHOPEE_ENV') || 'live';

const BASE_URL = SHOPEE_ENV === 'test'
  ? 'https://partner.test-stable.shopeemobile.com'
  : 'https://partner.shopeemobile.com';

// ── Utilitário: gerar assinatura HMAC-SHA256 ───────────────────────
function sign(path, timestamp, accessToken = '', shopId = 0) {
  const baseStr = shopId
    ? `${PARTNER_ID}${path}${timestamp}${accessToken}${shopId}`
    : `${PARTNER_ID}${path}${timestamp}`;
  return crypto.createHmac('sha256', PARTNER_KEY).update(baseStr).digest('hex');
}

// ── Utilitário: buscar config do token no Backendless ─────────────
async function getStoredToken() {
  const result = await Backendless.Data.of('ShopeeConfig').find(
    Backendless.DataQueryBuilder.create().setPageSize(1).setSortBy(['created DESC'])
  );
  if (!result.length || !result[0].accessToken) {
    throw new Error('Shopee não autorizado. Configure OAuth primeiro.');
  }
  return result[0];
}

// ── Utilitário: chamada autenticada à API da Shopee ────────────────
async function shopeeApiCall(path, params = {}, method = 'GET') {
  const cfg = await getStoredToken();
  const ts = Math.floor(Date.now() / 1000);
  const signature = sign(path, ts, cfg.accessToken, cfg.shopId);

  const url = new URL(`${BASE_URL}${path}`);
  url.searchParams.set('partner_id', PARTNER_ID);
  url.searchParams.set('timestamp', ts);
  url.searchParams.set('access_token', cfg.accessToken);
  url.searchParams.set('shop_id', cfg.shopId);
  url.searchParams.set('sign', signature);

  const fetchOpts = { method, headers: { 'Content-Type': 'application/json' } };
  if (method === 'POST') fetchOpts.body = JSON.stringify(params);
  else Object.entries(params).forEach(([k, v]) => url.searchParams.set(k, v));

  const res = await fetch(url.toString(), fetchOpts);
  const data = await res.json();

  if (data.error && data.error !== '') {
    if (data.error === 'error_auth' || data.message?.includes('token')) {
      throw new Error('TOKEN_EXPIRED:' + data.message);
    }
    throw new Error(`Shopee API error [${data.error}]: ${data.message}`);
  }
  return data;
}

// ═══════════════════════════════════════════════════
//  MÉTODO: ping — teste de conectividade
// ═══════════════════════════════════════════════════
Backendless.ServerCode.addService('shopee', 'ping', async () => {
  return { ok: true, pong: true, env: SHOPEE_ENV, timestamp: new Date().toISOString() };
});

// ═══════════════════════════════════════════════════
//  MÉTODO: getOAuthUrl — gera URL de autorização OAuth
// ═══════════════════════════════════════════════════
Backendless.ServerCode.addService('shopee', 'getOAuthUrl', async () => {
  const ts = Math.floor(Date.now() / 1000);
  const path = '/api/v2/shop/auth_partner';
  const signature = sign(path, ts);
  const authUrl = `${BASE_URL}${path}?partner_id=${PARTNER_ID}&timestamp=${ts}&sign=${signature}&redirect=${encodeURIComponent(REDIRECT_URL)}`;
  return { authUrl };
});

// ═══════════════════════════════════════════════════
//  MÉTODO: handleOAuthCallback — chamado após o redirect da Shopee
//  Params: { code, shopId }
//  (Crie uma página /shopee-callback.html no GitHub Pages que chame este endpoint)
// ═══════════════════════════════════════════════════
Backendless.ServerCode.addService('shopee', 'handleOAuthCallback', async ({ code, shopId }) => {
  if (!code || !shopId) throw new Error('code e shopId são obrigatórios');

  const ts = Math.floor(Date.now() / 1000);
  const path = '/api/v2/auth/token/get';
  const signature = sign(path, ts);

  const res = await fetch(`${BASE_URL}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code, shop_id: parseInt(shopId), partner_id: parseInt(PARTNER_ID), sign: signature, timestamp: ts }),
  });
  const data = await res.json();
  if (data.error) throw new Error(`OAuth error: ${data.message}`);

  // Salvar token com segurança no Backendless
  const existing = await Backendless.Data.of('ShopeeConfig').find(
    Backendless.DataQueryBuilder.create().setPageSize(1)
  );
  const tokenObj = {
    shopId: parseInt(shopId),
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    expiresAt: data.expire_in,
    refreshExpiresAt: data.refresh_token_expire_in,
    updatedAt: new Date().toISOString(),
  };
  if (existing.length) {
    tokenObj.objectId = existing[0].objectId;
    await Backendless.Data.of('ShopeeConfig').save(tokenObj);
  } else {
    await Backendless.Data.of('ShopeeConfig').save(tokenObj);
  }
  return { success: true, shopId };
});

// ═══════════════════════════════════════════════════
//  MÉTODO: checkToken — verifica validade
// ═══════════════════════════════════════════════════
Backendless.ServerCode.addService('shopee', 'checkToken', async () => {
  const cfg = await getStoredToken();
  const now = Math.floor(Date.now() / 1000);
  const valid = cfg.expiresAt && now < cfg.expiresAt;
  return { valid, expiresAt: cfg.expiresAt, shopId: cfg.shopId };
});

// ═══════════════════════════════════════════════════
//  MÉTODO: refreshToken — renova o access token
// ═══════════════════════════════════════════════════
Backendless.ServerCode.addService('shopee', 'refreshToken', async () => {
  const cfg = await getStoredToken();
  const ts = Math.floor(Date.now() / 1000);
  const path = '/api/v2/auth/access_token/get';
  const signature = sign(path, ts);

  const res = await fetch(`${BASE_URL}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      refresh_token: cfg.refreshToken,
      shop_id: cfg.shopId,
      partner_id: parseInt(PARTNER_ID),
      sign: signature,
      timestamp: ts,
    }),
  });
  const data = await res.json();
  if (data.error) throw new Error(`Refresh token error: ${data.message}`);

  // Atualiza no Backendless
  await Backendless.Data.of('ShopeeConfig').save({
    objectId: cfg.objectId,
    accessToken: data.access_token,
    refreshToken: data.refresh_token || cfg.refreshToken,
    expiresAt: data.expire_in,
    refreshExpiresAt: data.refresh_token_expire_in || cfg.refreshExpiresAt,
    updatedAt: new Date().toISOString(),
  });
  return { success: true };
});

// ═══════════════════════════════════════════════════
//  MÉTODO: revokeToken — revoga acesso
// ═══════════════════════════════════════════════════
Backendless.ServerCode.addService('shopee', 'revokeToken', async () => {
  const cfg = await getStoredToken();
  const ts = Math.floor(Date.now() / 1000);
  const path = '/api/v2/auth/cancel';
  const signature = sign(path, ts, cfg.accessToken, cfg.shopId);

  await fetch(`${BASE_URL}${path}?partner_id=${PARTNER_ID}&timestamp=${ts}&access_token=${cfg.accessToken}&shop_id=${cfg.shopId}&sign=${signature}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ shop_id: cfg.shopId }),
  });
  await Backendless.Data.of('ShopeeConfig').save({
    objectId: cfg.objectId,
    accessToken: '',
    refreshToken: '',
    expiresAt: 0,
    updatedAt: new Date().toISOString(),
  });
  return { success: true };
});

// ═══════════════════════════════════════════════════
//  MÉTODO: getOrders — busca pedidos da Shopee
//  Params: { daysBack?, orderStatus? }
// ═══════════════════════════════════════════════════
Backendless.ServerCode.addService('shopee', 'getOrders', async ({ daysBack = 7, orderStatus = 'COMPLETED' }) => {
  const now = Math.floor(Date.now() / 1000);
  const from = now - daysBack * 86400;

  // 1. Buscar lista de order_sn
  const listData = await shopeeApiCall('/api/v2/order/get_order_list', {
    time_range_field: 'create_time',
    time_from: from,
    time_to: now,
    page_size: 100,
    order_status: orderStatus.split(',')[0], // API aceita um status por vez
  });

  const orderList = listData.response?.order_list || [];
  if (!orderList.length) return { orders: [] };

  // 2. Buscar detalhes em lotes de 50
  const snList = orderList.map(o => o.order_sn);
  const chunks = [];
  for (let i = 0; i < snList.length; i += 50) chunks.push(snList.slice(i, i + 50));

  let orders = [];
  for (const chunk of chunks) {
    const detailData = await shopeeApiCall('/api/v2/order/get_order_detail', {
      order_sn_list: chunk.join(','),
      request_order_status_pending: true,
      request_buyer_info: true,
      request_item_info: true,
    });
    orders = orders.concat(detailData.response?.order_list || []);
  }
  return { orders };
});

// ═══════════════════════════════════════════════════
//  MÉTODO: getProducts — lista produtos da loja
// ═══════════════════════════════════════════════════
Backendless.ServerCode.addService('shopee', 'getProducts', async () => {
  const data = await shopeeApiCall('/api/v2/product/get_item_list', {
    offset: 0,
    page_size: 100,
    item_status: 'NORMAL',
  });
  const itemIds = (data.response?.item || []).map(i => i.item_id);
  if (!itemIds.length) return { items: [] };

  const detail = await shopeeApiCall('/api/v2/product/get_item_base_info', {
    item_id_list: itemIds.join(','),
    need_tax_info: false,
    need_complaint_policy: false,
  });
  return { items: detail.response?.item_list || [] };
});

// ═══════════════════════════════════════════════════
//  MÉTODO: updateStock — atualiza estoque de um produto
//  Params: { itemId, stock }
// ═══════════════════════════════════════════════════
Backendless.ServerCode.addService('shopee', 'updateStock', async ({ itemId, stock }) => {
  if (!itemId || stock === undefined) throw new Error('itemId e stock são obrigatórios');

  // Primeiro busca variações do produto
  const info = await shopeeApiCall('/api/v2/product/get_model_list', { item_id: parseInt(itemId) });
  const models = info.response?.model || [];

  // Atualiza estoque para cada variação (ou o item principal)
  const stockList = models.length
    ? models.map(m => ({ model_id: m.model_id, normal_stock: parseInt(stock) }))
    : [{ model_id: 0, normal_stock: parseInt(stock) }];

  const result = await shopeeApiCall('/api/v2/product/update_stock', {
    item_id: parseInt(itemId),
    stock_list: stockList,
  }, 'POST');

  return { success: true, result };
});

// ═══════════════════════════════════════════════════
//  TIMER AUTOMÁTICO — Backendless Scheduled Task
//  Configure em: Business Logic > Timers
//  Intervalo sugerido: a cada 30 minutos
//
//  Para criar via Backendless Console:
//  Nome: shopee_auto_sync
//  Frequência: */30 * * * *  (a cada 30min)
// ═══════════════════════════════════════════════════
Backendless.ServerCode.addTimer({
  name: 'shopee_auto_sync',
  startDate: Date.now(),
  frequency: { schedule: 'custom', cron: '0 */30 * * * *' }, // a cada 30min

  execute: async () => {
    console.log('[Shopee AutoSync] Iniciando sync automático...');
    try {
      // Verifica se token está válido
      const cfgList = await Backendless.Data.of('ShopeeConfig').find(
        Backendless.DataQueryBuilder.create().setPageSize(1).setSortBy(['created DESC'])
      );
      if (!cfgList.length || !cfgList[0].accessToken) {
        console.log('[Shopee AutoSync] Sem token configurado. Pulando.');
        return;
      }
      const now = Math.floor(Date.now() / 1000);
      const cfg = cfgList[0];

      // Renova token se expirado
      if (cfg.expiresAt && now >= cfg.expiresAt - 300) {
        console.log('[Shopee AutoSync] Token próximo de expirar, renovando...');
        const ts = now;
        const path = '/api/v2/auth/access_token/get';
        const signature = sign(path, ts);
        const res = await fetch(`${BASE_URL}${path}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ refresh_token: cfg.refreshToken, shop_id: cfg.shopId, partner_id: parseInt(PARTNER_ID), sign: signature, timestamp: ts }),
        });
        const data = await res.json();
        if (!data.error) {
          await Backendless.Data.of('ShopeeConfig').save({ objectId: cfg.objectId, accessToken: data.access_token, refreshToken: data.refresh_token || cfg.refreshToken, expiresAt: data.expire_in, updatedAt: new Date().toISOString() });
          console.log('[Shopee AutoSync] Token renovado.');
        }
      }

      // Busca novos pedidos (últimos 1 dia)
      const fromTs = now - 86400;
      const listData = await shopeeApiCall('/api/v2/order/get_order_list', { time_range_field: 'create_time', time_from: fromTs, time_to: now, page_size: 100, order_status: 'COMPLETED' });
      const orders = listData.response?.order_list || [];

      let saved = 0;
      for (const order of orders) {
        const existing = await Backendless.Data.of('ShopeePedidos').find(
          Backendless.DataQueryBuilder.create().setWhereClause(`orderId = '${order.order_sn}'`).setPageSize(1)
        );
        if (!existing.length) {
          await Backendless.Data.of('ShopeePedidos').save({
            orderId: order.order_sn, status: order.order_status,
            syncedAt: new Date().toISOString(), criadoEm: new Date(order.create_time * 1000).toISOString(),
          });
          saved++;
        }
      }

      // Log do sync
      await Backendless.Data.of('ShopeeSyncLogs').save({ tipo: 'auto_sync', status: 'success', mensagem: `Auto-sync: ${saved} novos pedidos`, criadoEm: new Date().toISOString() });
      console.log(`[Shopee AutoSync] Concluído: ${saved} novos pedidos.`);
    } catch (e) {
      console.error('[Shopee AutoSync] Erro:', e.message);
      await Backendless.Data.of('ShopeeSyncLogs').save({ tipo: 'auto_sync', status: 'error', mensagem: e.message, criadoEm: new Date().toISOString() }).catch(() => {});
    }
  },
});

/*
 * ══════════════════════════════════════════════════════════════════
 *  PÁGINA DE CALLBACK OAUTH — shopee-callback.html
 *  Salve este arquivo no seu repositório GitHub Pages
 * ══════════════════════════════════════════════════════════════════
 *
 * <!DOCTYPE html>
 * <html>
 * <head><title>Shopee Auth</title></head>
 * <body>
 * <p>Autorizando Shopee... <span id="msg"></span></p>
 * <script>
 *   const params = new URLSearchParams(window.location.search);
 *   const code   = params.get('code');
 *   const shopId = params.get('shop_id');
 *   if (code && shopId) {
 *     const BL_BASE = 'https://api.backendless.com/SEU_APP_ID/SEU_API_KEY';
 *     fetch(`${BL_BASE}/services/shopee/handleOAuthCallback`, {
 *       method: 'POST',
 *       headers: { 'Content-Type': 'application/json' },
 *       body: JSON.stringify({ code, shopId })
 *     })
 *     .then(r => r.json())
 *     .then(d => {
 *       document.getElementById('msg').textContent = '✅ Autorizado!';
 *       if (window.opener) {
 *         window.opener.postMessage({ type: 'SHOPEE_AUTH_SUCCESS' }, '*');
 *       }
 *       setTimeout(() => window.close(), 2000);
 *     })
 *     .catch(e => { document.getElementById('msg').textContent = '❌ Erro: ' + e.message; });
 *   } else {
 *     document.getElementById('msg').textContent = '❌ Parâmetros inválidos.';
 *   }
 * </script>
 * </body>
 * </html>
 *
 * ══════════════════════════════════════════════════════════════════
 *  TABELAS NECESSÁRIAS NO BACKENDLESS:
 * ══════════════════════════════════════════════════════════════════
 *
 *  ShopeeConfig:
 *    shopId (Number), accessToken (String), refreshToken (String),
 *    expiresAt (Number), refreshExpiresAt (Number), updatedAt (DateTime)
 *
 *  ShopeePedidos:
 *    orderId (String), status (String), total (Number),
 *    buyerName (String), buyerPhone (String), items (String/JSON),
 *    createdAt (DateTime), syncedAt (DateTime)
 *
 *  ShopeeProdutos:
 *    itemId (String), shopSku (String), name (String),
 *    price (Number), stock (Number), status (String), syncedAt (DateTime)
 *
 *  ShopeeSyncLogs:
 *    tipo (String), status (String), mensagem (String),
 *    detalhes (String), usuario (String), criadoEm (DateTime)
 *
 * ══════════════════════════════════════════════════════════════════
 *  VARIÁVEIS DE AMBIENTE (App Settings > App Environment):
 * ══════════════════════════════════════════════════════════════════
 *
 *  SHOPEE_PARTNER_ID   = 123456         (seu ID de parceiro)
 *  SHOPEE_PARTNER_KEY  = abc123xyz...   (sua chave secreta — NUNCA exposta ao front!)
 *  SHOPEE_REDIRECT_URL = https://seu-usuario.github.io/seu-repo/shopee-callback.html
 *  SHOPEE_ENV          = live           (ou "test" para sandbox)
 *
 * ══════════════════════════════════════════════════════════════════
 *  PASSO A PASSO COMPLETO:
 * ══════════════════════════════════════════════════════════════════
 *
 *  1. Registre-se no Shopee Open Platform: https://open.shopee.com
 *  2. Crie um App → obtenha Partner ID e Partner Key
 *  3. Configure o Redirect URL no portal Shopee (deve ser HTTPS)
 *  4. No Backendless Console:
 *     a. Business Logic > Services > Criar "shopee"
 *     b. Cole este código
 *     c. Em App Settings > App Environment, adicione as variáveis acima
 *     d. Crie as tabelas listadas acima em Data > Schema
 *     e. Business Logic > Timers > Criar "shopee_auto_sync" (cron: 0 */30 * * * *)
 *  5. Suba a shopee-callback.html no GitHub Pages
 *  6. No CRM: Shopee Sync > Configurações
 *     a. Informe a URL: https://api.backendless.com/APP_ID/API_KEY/services/shopee
 *     b. Salve e clique "Testar Conexão"
 *     c. Clique "Autorizar via Shopee OAuth"
 *     d. Faça login na Shopee e autorize
 *     e. Pronto! Use "Sincronizar Shopee" para importar tudo.
 */
