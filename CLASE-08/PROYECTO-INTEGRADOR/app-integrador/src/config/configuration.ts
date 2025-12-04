export default () => ({
  MONGO_URI: process.env.MONGO_URI,
  PORT: process.env.PORT,
  MODE: process.env.MODE,
  JWT_SECRET: process.env.JWT_SECRET,
  JWT_EXPIRES: process.env.JWT_EXPIRES,
});

