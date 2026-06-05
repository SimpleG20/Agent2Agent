// Carteira simulada — saldo em memoria
const { v4: uuidv4 } = require('uuid');

const DEFAULT_BALANCE = 20;

const wallets = new Map();
const transactions = [];

function createWallet(owner = 'anonymous') {
  const wallet = {
    id: uuidv4(),
    owner,
    balance: DEFAULT_BALANCE,
    createdAt: new Date().toISOString()
  };
  wallets.set(wallet.id, wallet);
  return wallet;
}

function getWallet(walletId) {
  return wallets.get(walletId) || null;
}

function getWalletByOwner(owner) {
  return Array.from(wallets.values()).find(w => w.owner === owner) || null;
}

function getBalance(walletId) {
  const wallet = wallets.get(walletId);
  return wallet ? wallet.balance : 0;
}

function debit(walletId, amount, description = '') {
  const wallet = wallets.get(walletId);
  if (!wallet) return { ok: false, error: 'Wallet not found' };
  if (wallet.balance < amount) return { ok: false, error: 'Insufficient credits' };

  wallet.balance -= amount;
  const tx = {
    id: uuidv4(),
    walletId,
    type: 'debit',
    amount,
    balanceAfter: wallet.balance,
    description,
    timestamp: new Date().toISOString()
  };
  transactions.push(tx);
  return { ok: true, transaction: tx };
}

function credit(walletId, amount, description = '') {
  const wallet = wallets.get(walletId);
  if (!wallet) return { ok: false, error: 'Wallet not found' };

  wallet.balance += amount;
  const tx = {
    id: uuidv4(),
    walletId,
    type: 'credit',
    amount,
    balanceAfter: wallet.balance,
    description,
    timestamp: new Date().toISOString()
  };
  transactions.push(tx);
  return { ok: true, transaction: tx };
}

function getHistory(walletId) {
  return transactions.filter(t => t.walletId === walletId);
}

function getOrCreateWallet(owner = 'anonymous') {
  let w = getWalletByOwner(owner);
  if (!w) w = createWallet(owner);
  return w;
}

// Seed wallet
createWallet('default');

module.exports = {
  createWallet, getWallet, getWalletByOwner,
  getBalance, debit, credit, getHistory, getOrCreateWallet
};
