export function linkedWalletOf(value) {
  if (!value || typeof value !== 'object' || (value.error ?? value.message) !== 'PROVIDER_ACCOUNT_BOUND') return undefined;
  return typeof value.linkedWallet === 'string' && /^0x[0-9a-f]{40}$/i.test(value.linkedWallet)
    && value.linkedWallet !== '0x' + '0'.repeat(40) ? value.linkedWallet.toLowerCase() : undefined;
}
export function accountBindingMessage(value) {
  const wallet = linkedWalletOf(value);
  return wallet ? `This account is already linked to wallet ${wallet}. Connect that wallet to continue.` : undefined;
}
