# Abstraction wallet
An smart security wallet for your digital assets.

## Features
1. Create wallet with passkey
2. OTP authentication before any transaction
3. Password recovery mechanism

## User flow
1. User creates a wallet by setting a passkey.
2. User can add guardians to their wallet as a OTP verification method.
3. Before any transaction, user must verify their identity using OTP sent to guardians.
4. User can add password recovery options in case they lost their passkey.
5. User can recover their wallet using the recovery options set earlier. (recovery process may also require OTP verification from guardians and take time delay for security)

## Security Considerations
1. Ensure strong encryption for passkeys and sensitive data.
2. Implement rate limiting for OTP requests to prevent abuse.
3. Regularly audit the security of the wallet and recovery mechanisms.
4. Educate users on best practices for securing their wallets and recovery options.
5. Use multi-factor authentication for added security during sensitive operations.
6. Monitor for suspicious activities and notify users of any unusual access attempts.
7. Ensure compliance with relevant regulations and standards for digital asset security.
8. Provide clear instructions and support for users during the recovery process to prevent social engineering attacks.
9. Regularly update the wallet software to patch vulnerabilities and improve security features.
10. Implement a secure backup mechanism for wallet data to prevent loss due to device failure.

## Operation authorization
### Without Guardian
- Normal transactions: passkeys required

