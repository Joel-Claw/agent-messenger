import { API_BASE } from './api';

// E2E encryption utilities using Web Crypto API
// Implements a simplified Signal Protocol (X3DH + AES-256-GCM)

const ALGORITHM = 'x25519-aes-256-gcm';

// Key storage keys
const STORAGE_KEYS = {
  identityPrivateKey: 'e2e_identity_private_key',
  identityPublicKey: 'e2e_identity_public_key',
  signedPreKeyPrivate: 'e2e_signed_prekey_private',
  signedPreKeyPublic: 'e2e_signed_prekey_public',
  sessionId: 'e2e_session_id',
};

export interface KeyPair {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}

export interface SerializedKeyPair {
  privateKey: string; // base64 JWK
  publicKey: string;  // base64 JWK
}

export interface PreKeyBundle {
  identity_key: {
    id: string;
    owner_id: string;
    owner_type: string;
    key_type: string;
    public_key: string; // base64 raw
    created_at: string;
  };
  signed_prekey?: {
    id: string;
    owner_id: string;
    owner_type: string;
    key_type: string;
    public_key: string;
    signature: string;
    created_at: string;
  };
  one_time_prekey?: {
    id: string;
    owner_id: string;
    owner_type: string;
    key_type: string;
    public_key: string;
    key_id: number;
    created_at: string;
  };
}

export interface EncryptedEnvelope {
  id?: string;
  conversation_id: string;
  ciphertext: string;
  iv: string;
  recipient_key_id: string;
  sender_key_id?: string;
  algorithm: string;
}

// --- Key Generation ---

export async function generateIdentityKeyPair(): Promise<KeyPair> {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'X25519' },
    true, // extractable
    ['deriveBits']
  );
  return keyPair as unknown as KeyPair;
}

export async function generateEphemeralKeyPair(): Promise<KeyPair> {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'X25519' },
    true,
    ['deriveBits']
  );
  return keyPair as unknown as KeyPair;
}

// --- Key Serialization ---

export async function exportPublicKey(key: CryptoKey): Promise<string> {
  const jwk = await crypto.subtle.exportKey('jwk', key);
  // For X25519, the public key is in the 'x' field (base64url)
  return jwk.x || '';
}

export async function exportPrivateKey(key: CryptoKey): Promise<string> {
  const jwk = await crypto.subtle.exportKey('jwk', key);
  return JSON.stringify(jwk);
}

export async function importPrivateKey(jwkStr: string): Promise<CryptoKey> {
  const jwk = JSON.parse(jwkStr);
  return crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'X25519' },
    true,
    ['deriveBits']
  );
}

export async function importPublicKey(base64Url: string): Promise<CryptoKey> {
  // Reconstruct JWK from raw x coordinate
  const jwk = {
    kty: 'OKP',
    crv: 'X25519',
    x: base64Url,
  };
  return crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'X25519' },
    true,
    []
  );
}

// --- X3DH Key Agreement ---

export async function x3dhKeyAgreement(
  myPrivateKey: CryptoKey,
  theirPublicKey: CryptoKey
): Promise<ArrayBuffer> {
  // Simple DH: shared secret = X25519(myPrivate, theirPublic)
  const sharedBits = await crypto.subtle.deriveBits(
    { name: 'X25519', public: theirPublicKey },
    myPrivateKey,
    256
  );
  return sharedBits;
}

// --- AES-256-GCM Encryption ---

export async function encryptMessage(
  plaintext: string,
  sharedKey: ArrayBuffer
): Promise<{ ciphertext: string; iv: string }> {
  // Derive AES key from shared secret using HKDF
  const aesKey = await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new TextEncoder().encode('agent-messenger-e2e'),
      info: new TextEncoder().encode('aes-256-gcm-key'),
    },
    await crypto.subtle.importKey('raw', sharedKey, 'HKDF', false, ['deriveKey']),
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);

  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    encoded
  );

  return {
    ciphertext: arrayBufferToBase64(encrypted),
    iv: arrayBufferToBase64(iv.buffer as ArrayBuffer),
  };
}

export async function decryptMessage(
  ciphertextB64: string,
  ivB64: string,
  sharedKey: ArrayBuffer
): Promise<string> {
  const aesKey = await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new TextEncoder().encode('agent-messenger-e2e'),
      info: new TextEncoder().encode('aes-256-gcm-key'),
    },
    await crypto.subtle.importKey('raw', sharedKey, 'HKDF', false, ['deriveKey']),
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  const ciphertext = base64ToArrayBuffer(ciphertextB64);
  const iv = base64ToArrayBuffer(ivB64);

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    ciphertext
  );

  return new TextDecoder().decode(decrypted);
}

// --- Session Management ---

export interface E2ESession {
  conversationId: string;
  theirPublicKeyB64: string;
  sharedKey?: ArrayBuffer;
  established: boolean;
}

const sessions: Map<string, E2ESession> = new Map();

export function getSession(conversationId: string): E2ESession | undefined {
  return sessions.get(conversationId);
}

export function setSession(conversationId: string, session: E2ESession): void {
  sessions.set(conversationId, session);
}

export function clearSession(conversationId: string): void {
  sessions.delete(conversationId);
}

// --- Full E2E Flow ---

export async function initializeE2E(token: string): Promise<void> {
  // Check if identity key already exists
  const storedPrivate = localStorage.getItem(STORAGE_KEYS.identityPrivateKey);
  const storedPublic = localStorage.getItem(STORAGE_KEYS.identityPublicKey);

  if (storedPrivate && storedPublic) {
    // Already initialized
    return;
  }

  // Generate identity key pair
  const identityPair = await generateIdentityKeyPair();
  const pubKeyB64 = await exportPublicKey(identityPair.publicKey);
  const privKeyJWK = await exportPrivateKey(identityPair.privateKey);

  // Upload identity public key to server
  const res = await fetch(`${API_BASE}/keys/upload`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({
      key_type: 'identity',
      public_key: pubKeyB64,
    }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Upload failed' }));
    throw new Error(err.error || 'Failed to upload identity key');
  }

  // Store locally
  localStorage.setItem(STORAGE_KEYS.identityPrivateKey, privKeyJWK);
  localStorage.setItem(STORAGE_KEYS.identityPublicKey, pubKeyB64);
}

export async function getLocalIdentityKey(): Promise<{ privateKey: CryptoKey; publicKeyB64: string } | null> {
  const privStr = localStorage.getItem(STORAGE_KEYS.identityPrivateKey);
  const pubB64 = localStorage.getItem(STORAGE_KEYS.identityPublicKey);
  if (!privStr || !pubB64) return null;

  const privateKey = await importPrivateKey(privStr);
  return { privateKey, publicKeyB64: pubB64 };
}

export async function establishSession(
  conversationId: string,
  theirOwnerId: string,
  theirOwnerType: string,
  token: string
): Promise<E2ESession> {
  // Check if session already established
  const existing = getSession(conversationId);
  if (existing?.established && existing.sharedKey) return existing;

  // Get their pre-key bundle from server
  const res = await fetch(
    `${API_BASE}/keys/bundle?owner_id=${encodeURIComponent(theirOwnerId)}&owner_type=${encodeURIComponent(theirOwnerType)}`,
    {
      headers: { Authorization: `Bearer ${token}` },
    }
  );

  if (!res.ok) {
    throw new Error('Failed to fetch key bundle — recipient may not have E2E set up');
  }

  const bundle: PreKeyBundle = await res.json();
  const theirIdentityPubB64 = bundle.identity_key.public_key;

  // Get our identity key
  const myKey = await getLocalIdentityKey();
  if (!myKey) throw new Error('Identity key not initialized');

  // Perform X3DH: shared = DH(myPrivate, theirPublic)
  const theirPubKey = await importPublicKey(theirIdentityPubB64);
  const sharedKey = await x3dhKeyAgreement(myKey.privateKey, theirPubKey);

  const session: E2ESession = {
    conversationId,
    theirPublicKeyB64: theirIdentityPubB64,
    sharedKey,
    established: true,
  };

  setSession(conversationId, session);
  return session;
}

export async function sendEncryptedMessage(
  conversationId: string,
  plaintext: string,
  recipientKeyId: string,
  token: string
): Promise<string> {
  const session = getSession(conversationId);
  if (!session?.sharedKey) throw new Error('E2E session not established');

  const { ciphertext, iv } = await encryptMessage(plaintext, session.sharedKey);

  const myKey = await getLocalIdentityKey();

  const res = await fetch(`${API_BASE}/messages/encrypted`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({
      conversation_id: conversationId,
      ciphertext,
      iv,
      recipient_key_id: recipientKeyId,
      sender_key_id: myKey?.publicKeyB64 || '',
      algorithm: ALGORITHM,
    }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Send failed' }));
    throw new Error(err.error || 'Failed to send encrypted message');
  }

  const data = await res.json();
  return data.id;
}

export async function decryptReceivedMessage(
  envelope: { ciphertext: string; iv: string },
  conversationId: string
): Promise<string> {
  const session = getSession(conversationId);
  if (!session?.sharedKey) throw new Error('E2E session not established');

  return decryptMessage(envelope.ciphertext, envelope.iv, session.sharedKey);
}

export function isE2EInitialized(): boolean {
  return !!localStorage.getItem(STORAGE_KEYS.identityPrivateKey);
}

export function resetE2E(): void {
  localStorage.removeItem(STORAGE_KEYS.identityPrivateKey);
  localStorage.removeItem(STORAGE_KEYS.identityPublicKey);
  localStorage.removeItem(STORAGE_KEYS.signedPreKeyPrivate);
  localStorage.removeItem(STORAGE_KEYS.signedPreKeyPublic);
  sessions.clear();
}

// --- Helpers ---

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}