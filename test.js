const bcrypt = require('bcryptjs');

bcrypt.hash('password123', 10).then(hash => {
  console.log('Hash:', hash);
}).catch(err => {
  console.error('Error:', err);
});
