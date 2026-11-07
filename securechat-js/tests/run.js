'use strict';
// Simple test runner: runs every test file and reports.
(async () => {
  console.log('Security tests');
  await require('./test_security').run();
  console.log('\nIntegration test');
  await require('./test_integration').run();
  console.log('\nAll tests passed.');
  process.exit(0);
})().catch((e) => { console.error('TEST FAILED:', e.message); process.exit(1); });
