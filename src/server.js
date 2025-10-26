const app = require('./app');
const { connect } = require('./db/mongoose');

const PORT = process.env.PORT || 4000;

async function start() {
  await connect();
  app.listen(PORT, () => console.log(`Server listening on ${PORT}`));
}

start().catch(err => {
  console.error('Startup error', err);
  process.exit(1);
});
