// ════════════════════════════════════════
// STRIPE WEBHOOK — Fonction serveur
//
// Un "webhook" c'est comme une sonnette :
// quand quelqu'un paie sur Stripe, Stripe
// appuie sur cette sonnette pour nous prévenir.
// On met alors l'utilisateur en "payant" dans Supabase.
// ════════════════════════════════════════

import { createClient } from '@supabase/supabase-js';

export default async (req) => {

  // On récupère les variables secrètes (stockées dans Netlify, jamais dans le code)
  const SUPABASE_URL        = Netlify.env.get('SUPABASE_URL');
  const SUPABASE_SECRET_KEY = Netlify.env.get('SUPABASE_SERVICE_KEY');
  const STRIPE_WEBHOOK_SECRET = Netlify.env.get('STRIPE_WEBHOOK_SECRET');

  // On lit le corps de la requête envoyée par Stripe
  const body = await req.text();
  const signature = req.headers.get('stripe-signature');

  // ── Vérification de la signature ──
  // Stripe signe chaque notification pour qu'on sache que c'est bien lui.
  // On vérifie cette signature manuellement (sans librairie lourde).
  let event;
  try {
    event = verifyStripeWebhook(body, signature, STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Signature Stripe invalide:', err.message);
    return new Response('Webhook error: ' + err.message, { status: 400 });
  }

  // ── On réagit uniquement aux paiements réussis ──
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const email   = session.customer_details?.email;

    if (email) {
      const db = createClient(SUPABASE_URL, SUPABASE_SECRET_KEY);

      // On cherche l'utilisateur par email et on le passe en "payant"
      // "upsert" = crée la ligne si elle n'existe pas, met à jour si elle existe
      const { error } = await db.from('users').upsert(
        { email: email, paid: true },
        { onConflict: 'email' }
      );

      if (error) {
        console.error('Erreur Supabase:', error.message);
        return new Response('DB error', { status: 500 });
      }

      console.log('Utilisateur passé en payant :', email);
    }
  }

  return new Response('OK', { status: 200 });
};

// ════════════════════════════════════════
// Vérification manuelle de la signature Stripe
// (evite d'importer toute la librairie Stripe)
// ════════════════════════════════════════
function verifyStripeWebhook(payload, signature, secret) {
  const parts = {};
  signature.split(',').forEach(part => {
    const [k, v] = part.split('=');
    parts[k] = v;
  });

  const timestamp = parts['t'];
  const sigReceived = parts['v1'];

  // On recalcule la signature attendue
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secret);
  const msgData = encoder.encode(`${timestamp}.${payload}`);

  // Web Crypto API (disponible dans les fonctions Netlify)
  return crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
    .then(key => crypto.subtle.sign('HMAC', key, msgData))
    .then(sig => {
      const sigComputed = Array.from(new Uint8Array(sig))
        .map(b => b.toString(16).padStart(2, '0')).join('');

      if (sigComputed !== sigReceived) {
        throw new Error('Signature invalide');
      }

      return JSON.parse(payload);
    });
}

export const config = {
  path: '/api/stripe-webhook'
};
