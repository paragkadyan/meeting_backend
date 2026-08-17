const webpush = require('web-push');

const vapidKeys = webpush.generateVAPIDKeys();

console.log('=== VAPID Keys Generated ===\n');
console.log('Add these to your .env file:\n');
console.log(`VAPID_PUBLIC_KEY=${vapidKeys.publicKey}`);
console.log(`VAPID_PRIVATE_KEY=${vapidKeys.privateKey}`);
console.log(`VAPID_SUBJECT=mailto:your-email@example.com`);
console.log('\nPUSH_NOTIFICATION_ASSETS_BASE_URL=/assets');
console.log('PUSH_NOTIFICATION_ICON_PATH=/assets/notification-icon.svg');
console.log('PUSH_NOTIFICATION_BADGE_PATH=/assets/notification-badge.svg');
